# Copyright (c) 2020 Ashok P. Nadkarni
# All rights reserved.
# See LICENSE file for details.

# Implements the OPP profile

namespace eval obex::opp {}

oo::class create obex::opp::Client {
    superclass ::obex::Client

    method bt_uuid {} {
        # Returns the Bluetooth UUID for the service class for this profile.
        return 00001105-0000-1000-8000-00805f9b34fb
    }

    method push_file {chan path {mimetype {}}} {
        # Pushes the specified file over the given channel.
        #  chan - Channel to the remote server.
        #  path - Local path to the file.
        # The contents of the file are sent over the channel to the remote
        # server. The base name of the file is passed in a `Name` header.
        # The action taken by the server on receiving the file is
        # implementation dependent. In most cases, the server will store
        # the file in the current default location.
        #
        # For efficiency purposes, the method will also do a `CONNECT`
        # request if not already connected. This allows use of larger
        # packets.
        #
        # The method is synchronous and will block until completion and
        # will raise an error if the transfer was not successful.
        # 

        set file_size [file size $path]
        set from [open $path rb]

        # Save original config of output channel
        set chan_config [chan configure $chan]
        chan configure $chan -blocking 1 -buffering none \
            -translation binary
        try {
            # Connect to make use of larger packet sizes.
            if {![my connected]} {
                if {[my await $chan [my connect]] ne "done" ||
                    [my status] ne "success"
                } {
                    # Failed but no matter. We will go ahead without
                    # a connection. But need to reset state first.
                    my reset
                }
            }
            # Most often transfer packet size will be 64K. So
            # So make chunk size a little less to allow for headers.
            # We pass in the Length header because my Redmi File Manager
            # mandates it (otherwise server internalerror is returned)
            # although optional in the specification.
            set headers [list Name [file tail $path] Length $file_size]
            if {$mimetype ne ""} {
                # Mimetype header is supposed to have a terminating \0.
                # Add one if not present
                if {[string index $mimetype end] ne "\0"} {
                    append mimetype "\0"
                }
                lappend headers Type $mimetype
            }
            while {1} {
                set chunk [read $from 65000]
                set result [my Await $chan [my put_stream $chunk $headers]]
                if {$result ne "writable"} {
                    break
                }
                set headers {}
            }
            if {$result eq "done" && [my status] eq "success"}  {
                return
            } else {
                my RaiseError "File push failed."
            }
        } finally {
            close $from 

            # Restore original config. Note -encoding and -eofchar
            # need explicitly set as -translation binary above
            # changes them but not changed back by -translation below.
            chan configure $chan \
                -blocking [dict get $chan_config -blocking] \
                -buffering [dict get $chan_config -buffering] \
                -encoding [dict get $chan_config -encoding] \
                -translation [dict get $chan_config -translation] \
                -eofchar [dict get $chan_config -eofchar]
        }
    }

    method pull_card {chan} {
        # Retrieves the business card from the device.
        #  chan - Channel connected to the device.
        # 
        # The method is synchronous and will raise an error on failure.
        #
        # Returns the business card in vCard format.
        set headers [list Type "text/x-vcard\0"]
        set result [my await $chan [my get $headers]]
        if {$result eq "done" && [my status] eq "success"}  {
            return [join [my bodies]]
        } else {
            my RaiseError "Failed to pull business card."
        }
    }

    method exchange_cards {chan vcard {mimetype {}}} {
        # Exchanges business cards with a device.
        #  chan - Channel connected to device.
        # Sends the business card $vcard to the remote
        # device and retrieves the one from the device.
        #
        # The method is synchronous and will raise an error on failure.
        #
        # Returns the business card from the remote device.
        
        # We will send first and then pull so any meta data headers
        # will be preserved in headers_in.

        if {$mimetype eq ""} {
            set headers [list Type "text/vcard\0"]
        } else {
            # Mimetype header is supposed to have a terminating \0.
            # Add one if not present
            if {[string index $mimetype end] ne "\0"} {
                append mimetype "\0"
            }
            set headers [list Type $mimetype]
        }
        set result [my await $chan [my put $vcard $headers]]
        if {$result ne "done" || [my status] ne "success"}  {
            my RaiseError "Failed to send business card."
        } 
        return [my pull_card $chan]
    }
}
