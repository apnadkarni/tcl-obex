# Copyright (c) 2020 Ashok P. Nadkarni
# All rights reserved.
# See LICENSE file for details.

# Implements the OPP profile

namespace eval obex::opp {}

proc obex::opp::bt_uuid {} {
    # Returns the Bluetooth UUID for the service class for the
    # Object Push Profile.
    return 00001105-0000-1000-8000-00805f9b34fb
}


oo::class create obex::opp::Client {
    superclass ::obex::Client

    variable _chan
    variable _chan_config

    constructor {chan args} {
        # Creates a client object for the OBEX Object Push Profile.
        #  chan - Tcl channel to the remote server
        #
        # The passed channel will be configured for OBEX communication and
        # should not be used for any other purpose until the [close] method is
        # called.
        #
        # After all objects are transferred, the [close] method should be
        # called to disconnect the OBEX connection. Some servers will not
        # commit the sent objects until the OBEX connection is ended.
        # Note closing the passed Tcl channel does not suffice for this.

        if {[llength [self next]]} {
            next {*}$args
        }

        # Save original config of output channel and set it up for OBEX
        set _chan_config [chan configure $chan]
        chan configure $chan -blocking 1 -buffering none \
            -translation binary
        set _chan $chan
    }

    method close {} {
        # Closes an OBEX connection.
        # Returns the Tcl channel that was used for communication.

        if {![info exists _chan]} {
            my RaiseError "No channel attached."
        }
        set chan $_chan
        unset _chan

        try {
            if {[my connected]} {
                if {[my await $chan [my disconnect]] ne "done" ||
                    [my status] ne "success"
                } {
                    my RaiseError "Failed to close OBEX connection."
                }
            }
        } finally {
            # Restore original channel config. Note -encoding and -eofchar
            # need explicitly set as -translation binary above
            # changes them but not changed back by -translation below.
            chan configure $chan \
                -blocking [dict get $_chan_config -blocking] \
                -buffering [dict get $_chan_config -buffering] \
                -encoding [dict get $_chan_config -encoding] \
                -translation [dict get $_chan_config -translation] \
                -eofchar [dict get $_chan_config -eofchar]
        }

        return $chan
    }

    method EnsureConnected {} {
        if {![info exists _chan]} {
            my RaiseError "No channel attached."
        }
        if {![my connected]} {
            if {[my await $_chan [my connect]] ne "done" ||
                [my status] ne "success"
            } {
                my RaiseError "Failed to close OBEX connection."
            }
        }
    }

    method push_file {path {mimetype {}}} {
        # Pushes the specified file over the given channel.
        #  path - Local path to the file.
        #  mimetype - The MIME type for the file.
        # Establishes an OBEX connection to the server if one does not
        # already exist and sends the content of the file.
        # The base name of the file is passed as the object name.
        # The action taken by the server on receiving the file is
        # implementation dependent. In most cases, the server will store
        # the file in the current default location.
        #
        # Some OBEX servers will not accept files if the file extension
        # is not known to them. In such cases, the MIME type must be
        # passed in.
        #
        # The method is synchronous and will block until completion and
        # will raise an error if the transfer was not successful.
        # The [clear] method must be called in the latter case before any
        # further methods are called on the object.
        # 

        set file_size [file size $path]
        set from [open $path rb]

        try {
            my EnsureConnected

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
                set result [my Await $_chan [my put_stream $chunk $headers]]
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
        }
    }

    method pull_card {} {
        # Retrieves the business card from the device.
        #  chan - Channel connected to the device.
        # 
        # The method is synchronous and will raise an error on failure.
        # The [clear] method must be called in case of error before
        # further methods are called on the object.
        #
        # Returns the business card in vCard format.

        my EnsureConnected
        set headers [list Type "text/x-vcard\0"]
        set result [my await $_chan [my get $headers]]
        if {$result eq "done" && [my status] eq "success"}  {
            return [join [my bodies]]
        } else {
            my RaiseError "Failed to pull business card."
        }
    }

    method exchange_cards {vcard {mimetype {}}} {
        # Exchanges business cards with a device.
        #  vcard - Content of vCard
        #  mimetype - MIME type to use for $vcard. If unspecified, the
        #    MIME type `text/x-vard` is used.
        # Sends the business card $vcard to the remote
        # device and retrieves the one from the device.
        #
        # The method is synchronous and will raise an error on failure.
        # The [clear] method must be called in case of error before
        # further methods are called on the object.
        #
        # Returns the business card from the remote device in vCard format.
        
        # We will send first and then pull so any meta data headers
        # will be preserved in headers_in.

        my EnsureConnected
        if {$mimetype eq ""} {
            set headers [list Type "text/x-vcard\0"]
        } else {
            # Mimetype header is supposed to have a terminating \0.
            # Add one if not present
            if {[string index $mimetype end] ne "\0"} {
                append mimetype "\0"
            }
            set headers [list Type $mimetype]
        }
        set result [my await $_chan [my put $vcard $headers]]
        if {$result ne "done" || [my status] ne "success"}  {
            my RaiseError "Failed to send business card."
        } 
        return [my pull_card $_chan]
    }
}
