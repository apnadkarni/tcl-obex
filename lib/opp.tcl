# Copyright (c) 2020 Ashok P. Nadkarni
# All rights reserved.
# See LICENSE file for details.

# Implements the OPP profile

namespace eval obex::opp {}

oo::class create obex::opp::Client {
    superclass ::obex::Client

    method push_file {chan path} {
        # Pushes the specified file over the given channel.
        #  chan - Channel to the remote server.
        #  path - Local path to the file.
        # The contents of the file are sent over the channel to the remote
        # server. The base name of the file is passed in a `Name` header.
        # The action taken by the server on receiving the file is
        # implementation dependent. In most cases, the server will store
        # the file in the current default location.
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
            # Most often transfer packet size will be 64K. So
            # So make chunk size a little less to allow for headers.
            # We pass in the Length header because my Redmi File Manager
            # mandates it (otherwise server internalerror is returned)
            # although optional in the specification.
            set headers [list Name [file tail $path] Length $file_size]
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
}
