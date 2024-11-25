#
# Copyright (c) 2020, Ashok P. Nadkarni
# All rights reserved.
#
# See the file LICENSE for license

namespace eval obex {
    variable version 0.1.1

    # This script name and where it resides
    variable script [file tail [info script]]
    variable dir [file dirname [info script]]

    # Source files other than this one
    variable other_scripts {opp.tcl}

    # Are we a module?
    variable is_module [string equal -nocase [file ext $script] .tm]
}

namespace eval obex::core {

    variable id_counter 1
    proc GenerateId {} {
        variable id_counter
        # Hope it does not wrap
        if {$id_counter == 0xffffffff} {
            error "Id generator wrapped."
        }
        return [incr id_counter]
    }

    namespace eval packet {
        namespace path [namespace parent]
        namespace export length complete
        namespace ensemble create
    }

    namespace eval request {
        namespace path [namespace parent]
        namespace export encode decode encode_setpath
        namespace ensemble create

        variable OpNames
        variable OpCodes
    }

    namespace eval response {
        namespace path [namespace parent]
        namespace export encode decode
        namespace ensemble create

        variable ResponseCodeNames
        variable ResponseCodes
    }

    namespace eval header {
        namespace path [namespace parent]
        namespace export encode encoden decode decoden find findall
        namespace ensemble create

        variable Ids
        variable Names
    }

    namespace eval parameters {
        namespace path [namespace parent]
        namespace export decode
        namespace ensemble create
    }
}


proc obex::core::request::encode {op args} {
    # Encodes an OBEX request.
    #  op - A numeric request opcode or a opcode [mnemonic][OBEX operations].
    #  args - Alternating list of [header names][OBEX headers] and values.
    #    This may also be provided as a single argument of the same form.
    # Encodes a OBEX packet containing the specified opcode and headers.
    # No length checks are made and caller is responsible for ensuring the
    # generated packet length does not exceed the maximum packet size
    # for the OBEX connection.
    #
    # Returns the encoded packet.
    set op [OpCode $op]
    if {$op == 0x80} {
        return [EncodeConnect {*}$args]
    } elseif {$op == 0x87} {
        return [encode_setpath 0 0 {*}$args]
    }
    # Generic request encoder
    set headers [join [header encoden {*}$args] ""]
    # Packet is opcode, 2 bytes length, followed by headers
    set len [expr {3+[string length $headers]}]
    append packet [binary format cSu $op $len] $headers
    return $packet

}

proc obex::core::request::decode {packet outvar} {
    # Decodes an OBEX request packet received from a client.
    #  packet - Binary OBEX packet.
    #  outvar - name of variable in caller's context where the decoded packet
    #    is to be stored.
    #
    # If $packet contains a complete OBEX packet, the command stores the
    # decoded packet in the variable names $outvar in the caller's context.
    # The value is in the form of a dictionary with the following keys:
    #  PacketLength - Length of packet.
    #  OpCode       - Numeric request opcode.
    #  OpName       - Mnemonic opcode name.
    #
    #  Final        - 1/0 depending on whether the `final` bit was set
    #                 in the request opcode or not.
    #  Headers      - List of headers received in the packet.
    #
    # In case the packet was a `connect` request, the dictionary also
    # contains the following keys:
    #  Flags        - Always 0 for OBEX 1.0
    #  MaxLength    - Maximum length OBEX packet length the server can
    #                 receive.
    #  MajorVersion - The OBEX protocol major version returned by server.
    #  MinorVersion - The OBEX protocol minor version returned by server.
    #
    # In case the packet was a `setpath` request, the dictionary also
    # contains the following keys:
    #  Flags        - The flags field from the request.
    #  Constants    - The constants field from the request.
    #
    # Returns 1 if the packet was decoded or 0 if it is incomplete.
    upvar 1 $outvar decoded_packet
    if {[binary scan $packet cuSu op len] != 2 ||
        $len > [string length $packet]} {
        return 0
    }
    if {$op == 0x80} {
        # CONNECT request
        # Packet is opcode 0x80, 2 bytes length, version (1.0->0x10),
        # flags (0), 2 bytes max len followed by headers
        if {[binary scan $packet x3cucuSu version flags maxlen] != 3} {
            return 0
        }
        set decoded_packet [list \
                                PacketLength $len \
                                OpCode $op \
                                Final  [expr {($op & 0x80) == 0x80}] \
                                OpName [OpName $op] \
                                MajorVersion [expr {$version >> 4}] \
                                MinorVersion [expr {$version & 0xf}] \
                                Flags  $flags \
                                MaxLength $maxlen \
                                Headers [header decoden $packet 7] \
                               ]
    } elseif {$op == 0x87} {
        # SETPATH request
        if {[binary scan $packet x3cucu flags constants] != 2} {
            return 0
        }
        set decoded_packet [list \
                                PacketLength $len \
                                OpCode $op \
                                Final  [expr {($op & 0x80) == 0x80}] \
                                OpName [OpName $op] \
                                Flags  $flags \
                                Constants $constants \
                                Headers [header decoden $packet 5] \
                               ]
    } else {
        set decoded_packet [list \
                                PacketLength $len \
                                OpCode $op \
                                OpName [OpName $op] \
                                Final  [expr {($op & 0x80) == 0x80}] \
                                Headers [header decoden $packet 3] \
                               ]
    }
    return 1
}

proc obex::core::request::EncodeConnect {args} {
    set headers [join [header encoden {*}$args] ""]
    # Packet is opcode 0x80, 2 bytes length, version (1.0->0x10),
    # flags (0), 2 bytes max len
    # followed by headers
    set len [expr {7+[string length $headers]}]
    # Max acceptable packet length 65535
    append packet [binary format cuSucucuSu 0x80 $len 0x10 0 65535] $headers
    return $packet
}

proc obex::core::request::encode_setpath {flags constants args} {
    # Encodes a `setpath` OBEX request.
    #  flags - Numeric value to send for the flags field in the `setpath`
    #    request.
    #  constants - Numeric value to send for the constants field in the request
    #  args - Alternating list of [header names][OBEX headers] and values.
    #    This may also be provided as a single argument of the same form.
    # This command can be used in lieu of the [request encode] command when the
    # `setpath` request needs to include values for the `flags` or `constants`
    # fields.
    #
    # No length checks are made and caller is responsible for ensuring the
    # generated packet length does not exceed the maximum packet size
    # for the OBEX connection.
    #
    # Returns an encoded OBEX `setpath` request packet.

    set headers [join [header encoden {*}$args] ""]
    # Packet is opcode 0x85, 2 bytes length,
    # flags, constants, # followed by headers
    set len [expr {5+[string length $headers]}]
    append packet [binary format cuSucucu 0x85 $len flags constants] $headers
    return $packet
}

proc obex::core::response::decode {packet request_op outvar} {
    # Decodes a response packet.
    #  packet - Binary OBEX packet.
    #  request_op - The request opcode corresponding to this response.
    #  outvar - name of variable in caller's context where the decoded packet
    #    is to be stored.
    #
    # The dictionary stored in $outvar has the following keys:
    #  PacketLength       - Length of packet.
    #  Final        - 1/0 depending on whether the `final` bit was set
    #                 in the response operation code or not.
    #  Headers      - List of headers received in the packet.
    #  ResponseStatus       - The general status category.
    #  ResponseCode   - The numeric response status code from server.
    #
    # In case the response was for a `connect` request, the dictionary also
    # contains the following keys:
    #  Flags        - As returned by serve. Always 0 for OBEX 1.0
    #  MaxLength    - Maximum length OBEX packet length the server can
    #                 receive.
    #  MajorVersion - The OBEX protocol major version returned by server.
    #  MinorVersion - The OBEX protocol minor version returned by server.
    #
    # Returns 1 if the packet was decoded or 0 if it is incomplete.

    # TBD - do we need to check for ABORT packet as well?

    if {[binary scan $packet cuSu status len] != 2 ||
        $len > [string length $packet]} {
        return 0
    }

    upvar 1 $outvar decoded_packet

    set request_op [request::OpCode $request_op]
    if {$request_op == 0x80} {
        return [DecodeConnect $packet decoded_packet]
    }

    set decoded_packet [list \
                            PacketLength     $len \
                            ResponseCode $status \
                            ResponseStatus   [ResponseStatus $status] \
                            Final      [expr {($status & 0x80) == 0x80}] \
                            Headers    [header decoden $packet 3] \
                           ]
    return 1
}

proc obex::core::response::DecodeConnect {packet outvar} {
    # Decodes a OBEX response to a connect request.
    #  packet - Binary OBEX packet.
    #  outvar - name of variable in caller's context where the decoded packet
    #    is to be stored.
    #
    # The dictionary returned by the command has the following keys:
    #  PacketLength       - Length of packet.
    #  Final        - 1/0 depending on whether the `final` bit was set
    #                 in the response operation code or not.
    #  Headers      - List of headers received in the packet.
    #  ResponseStatus       - The general status category.
    #  ResponseCode   - The numeric status code from server.
    #  Flags        - Currently always 0.
    #  MaxLength    - Maximum length OBEX packet length the server can
    #                 receive.
    #  MajorVersion - The OBEX protocol major version returned by server.
    #  MinorVersion - The OBEX protocol minor version returned by server.

    # OBEX Section 3.3.18 - 0xa0 success, any other response is a failure.
    # It is still supposed to include same fields
    if {[binary scan $packet cuSucucuSu status len version flags maxlen] != 5 ||
        $len > [string length $packet]} {
        return 0
    }
    upvar 1 $outvar decoded_packet
    set decoded_packet [list \
                            PacketLength $len \
                            ResponseCode $status \
                            ResponseStatus [ResponseStatus $status] \
                            Final  [expr {($status & 0x80) == 0x80}] \
                            MajorVersion [expr {$version >> 4}] \
                            MinorVersion [expr {$version & 0xf}] \
                            Flags  $flags \
                            MaxLength $maxlen \
                            Headers [header decoden $packet 7] \
                           ]
    return 1
}

proc obex::core::packet::length {packet} {
    # Get the length of a packet.
    #  packet - an OBEX packet or the initial fragment of one with
    #           at least three bytes.
    # Returns the packet length as encoded in its header or 0 if the passed
    # fragment is too short to contain a length field.

    if {[binary scan $packet xSu len] != 1} {
        return 0
    }
    return $len
}

proc obex::core::packet::complete {packet} {
    # Returns 1 if $packet is a complete Obex packet and 0 otherwise.
    #  packet - an OBEX packet or fragment.
    if {[binary scan $packet xSu -> len] != 1} {
        return 0
    }
    return [expr {$len <= [string length $packet]}]
}

proc obex::core::header::encode {header_name header_value} {
    # Encodes a single OBEX header.
    #  header_name - The [header identifier][::obex::OBEX headers] name.
    #  header_value - The value to encode. For binary header types, it is
    #    caller's responsibility to pass this as a proper binary string.
    #
    # Returns the encoded header binary string.
    set hi [Id $header_name]
    # Top 2 bits encode data type
    switch -exact -- [expr {$hi >> 6}] {
        0 {
            # Encode as big-endian unicode
            set unicode_be [ToUnicodeBE $header_value]
            # Add a length field where the length includes 3 bytes for Header byte
            # and 2 bytes for length, and the 2 bytes for terminating Unicode null.
            set hlen [expr {3+[string length $unicode_be]+2}]
            append encoded [binary format cS $hi $hlen] $unicode_be "\0\0"
            return $encoded
        }
        1 {
            # Just an array of bytes. Caller has to ensure that is what it  is.
            set hlen [expr {3 + [string length $header_value]}]
            append encoded [binary format cS $hi $hlen] $header_value
            return $encoded
        }
        2 {
            # Single byte. Always room since space_left check at top
            return [binary format cc $hi $header_value]
        }
        3 {
            # Big endian 4 bytes
            return [binary format cI $hi $header_value]
        }
    }
}

proc obex::core::header::encoden {args} {
    # Encodes multiple OBEX headers.
    #  args - Alternating list of [header names][OBEX headers] and values.
    #    This may also be provided as a single argument of the same form.
    #    For binary header types, it is
    #    caller's responsibility to pass the values as a proper binary string.
    #
    # Returns the encoded headers as a list of binary strings.
    if {[llength $args] == 1} {
        set args [lindex $args 0]
    }
    set headers {}
    foreach {name value} $args {
        lappend headers [encode $name $value]
    }
    return $headers
}

proc obex::core::header::DecodeFirst {bytes start} {
    if {[binary scan $bytes x${start}cu hid] != 1} {
        error "Empty Obex header"
    }
    set trailing_len [expr {[string length $bytes] - $start}]
    set name [Name $hid]
    switch -exact -- [expr {$hid >> 6}] {
        0 {
            # Null-terminated Unicode string
            # Length must be at least 5 bytes - header id,2-byte len and terminating \0\0
            # Also, the string must have enough bytes for the indicated header length.
            # Skip $start bytes, skip hid byte
            if {[binary scan $bytes x${start}xSu len] != 1 ||
                $len < 5 ||
                $len > $trailing_len} {
                error "Invalid Obex header length."
            }
            # Note last byte of unicode is 3 bytes from end
            # (2 null bytes and 0-based index)
            set value [FromUnicodeBE [string range $bytes [expr {$start+3}] [expr {$start+$len-3}]]]
        }
        1 {
            # Raw bytes
            # Length must be at least 3 bytes - header id,2-byte len.
            # Also, the string must have enough bytes for the indicated header length.
            # Skip $start bytes, skip hid byte
            if {[binary scan $bytes x${start}xSu len] != 1 ||
                $len < 3 ||
                $len > $trailing_len} {
                error "Invalid Obex header length."
            }
            set value [string range $bytes [expr {$start+3}] [expr {$start+$len-1}]]
        }
        2 {
            # Single byte value. Always treated as unsigned 8 bits
            # Caller will need to convert to signed 8-bits if desired.
            if {2 > $trailing_len} {
                error "Invalid Obex header length."
            }
            set len 2
            binary scan $bytes x${start}xc value
        }
        3 {
            # 4-byte byte value. Always treated as signed 32 bits
            # Caller will need to convert to signed 32-bits if desired.
            if {5 > $trailing_len} {
                error "Invalid Obex header length."
            }
            set len 5
            binary scan $bytes x${start}xI value
        }
    }

    # Return the name, the value and the new offset for next header element
    return [list $name $value [expr {$start+$len}]]
}

proc obex::core::header::decoden {bytes start} {
    # Decodes binary OBEX headers within a packet.
    #  bytes - Binary string containing headers.
    #  start - Offset into $bytes where the headers start.
    # Returns a list of headers as dictionaries with
    # [header names][OBEX headers] as keys.
    set nbytes [string length $bytes]
    set headers {}
    while {$start < $nbytes} {
        lassign [DecodeFirst $bytes $start] name value start
        lappend headers $name $value
    }
    return $headers
}

proc obex::core::header::decode {bytes start} {
    # Decodes a single binary OBEX header within a packet.
    #  bytes - Binary string containing a header.
    #  start - Offset into $bytes where the header starts.
    # Returns a pair consisting of the [header name][OBEX headers]
    # and value.
    return [lrange [DecodeFirst $bytes $start] 0 1]
}

proc obex::core::header::find {headers header_name outvar} {
    # Gets the value of a header from a list of decoded OBEX headers.
    #  headers - list of decoded OBEX headers.
    #  header_name - [Header name][OBEX headers] to retrieve.
    #  outvar - Name of variable in caller's context where to store
    #   the header value.
    # If multiple headers of the same name exist, returns the value of
    # the first in the list.
    #
    # Returns 1 if the header is found and stores its value in $outvar;
    # otherwise returns 0.
    foreach {name val} $headers {
        if {[string equal -nocase $header_name $name]} {
            upvar 1 $outvar v
            set v $val
            return 1
        }
    }
    return 0
}

proc obex::core::header::findall {headers header_name} {
    # Gets the values of headers with a given name in list of
    # decoded OBEX headers
    #  headers - list of decoded OBEX headers.
    #  header_name - [Header name][OBEX headers] to retrieve.
    # Returns the list of values from headers that matched $header_name.
    return [lmap {name val} $headers {
        if {![string equal -nocase $header_name $name]} {
            continue
        }
        set val
    }]
}

proc obex::core::parameters::DecodeFirst {bytes start} {
    # Returns the first application parameter in a AppParameters header
    #  bytes - binary string containing app parameters
    #  start - where the app parameter starts

    if {[binary scan $bytes x${start}cucu tag length] != 1} {
        error "Truncated application parameter header."
    }

    set trailing_len [expr {[string length $bytes] - $start}]
    # Length must be at least 2 bytes - tag + length byte
    # Also, the string must have enough bytes for the length.
    if {[binary scan $bytes x${start}cucu tag len] != 2 ||
        $len < 2 ||
        $len > $trailing_len} {
        error "Invalid Obex application parameter length."
    }
    set value [string range $bytes [expr {$start+2}] [expr {$start+$len-1}]]

    # Return the name, the value and the new offset for next header element
    return [list $tag $value [expr {$start+$len}]]
}

proc obex::core::parameters::decode {bytes} {
    # Decodes a [AppParameters][OBEX headers] header value.
    #  bytes - binary containing the header value
    # Returns a list of containg the integer application parameter
    # tag alternating with the corresponding binary string value.
    set nbytes [string length $bytes]
    set params {}
    set start 0
    while {$start < $nbytes} {
        lassign [DecodeFirst $bytes $start] tag value start
        lappend params $tag $value
    }
    return $params
}

if {$::tcl_platform(byteOrder) eq "littleEndian"} {
    proc obex::core::ToUnicodeBE {s} {
        set be ""
        set le [encoding convertto unicode $s]
        set n [string length $le]
        # TBD - measure alternate ways. E.g split into list
        for {set i 0} {$i < $n} {incr i 2} {
            append be [string index $le $i+1] [string index $le $i]
        }
        return $be
    }
    proc obex::core::FromUnicodeBE {be} {
        set le ""
        set n [string length $be]
        for {set i 0} {$i < $n} {incr i 2} {
            append le [string index $be $i+1] [string index $be $i]
        }
        return [encoding convertfrom unicode $le]
    }
} else {
    proc obex::core::ToUnicodeBE {s} {
        return [encoding convertto unicode $s]
    }
    proc obex::core::FromUnicodeBE {be} {
        return [encoding convertfrom unicode $be]
    }
}

proc obex::core::MakeBinUuid {uuid} {
    if {![regexp {^[[:xdigit:]]{8}-([[:xdigit:]]{4}-){3}[[:xdigit:]]{12}$} $uuid]} {
       error "Invalid UUID."
    }
    return [binary decode hex [string map {- {}} $uuid]]
}

proc obex::core::request::OpName {op} {
    variable OpNames
    array set OpNames {
        0x80 connect
        0x81 disconnect
        0x02 put
        0x82 put
        0x03 get
        0x83 get
        0x85 setpath
        0x87 session
        0xff abort
    }
    proc OpName {op} {
        variable OpNames
        if {[string is integer -strict $op] && $op <= 0xff} {
            set op [format 0x%2.2X $op]
            if {[info exists OpNames($op)]} {
                return $OpNames($op)
            }
            return Request_$op
        }
        # If a name, verify it is valid by calling OpCode
        OpCode $op
        return $op
    }
    return [OpName $op]
}

proc obex::core::request::OpCode {op} {
    variable OpCodes
    # Note OpCodes and OpNames are not symmetrical
    array set OpCodes {
        connect     0x80
        disconnect  0x81
        put         0x02
        get         0x03
        setpath     0x85
        session     0x87
        abort       0xff
    }
    proc OpCode {op} {
        variable OpCodes
        if {[string is integer -strict $op]} {
            if {$op > 0 && $op < 256} {
                return $op
            }
        } else {
            if {[info exists OpCodes($op)]} {
                return $OpCodes($op)
            }
        }
        error "Invalid request code \"$op\"."
    }
    return [OpCode $op]
}

proc obex::core::response::ResponseCodeName {op} {
    variable ResponseCodeNames
    # Hex -> name
    # Note 0x01 - 0x0f -> not defined in spec. Used by us internally.
    array set ResponseCodeNames {
        0x10 continue
        0x20 ok
        0x21 created
        0x22 accepted
        0x23 non-authoritative
        0x24 nocontent
        0x25 resetcontent
        0x26 partialcontent
        0x30 multiplechoices
        0x31 movedpermanently
        0x32 movedtemporarily
        0x33 seeother
        0x34 notmodified
        0x35 useproxy
        0x40 badrequest
        0x41 unauthorized
        0x42 paymentrequired
        0x43 forbidden
        0x44 notfound
        0x45 methodnotallowed
        0x46 notacceptable
        0x47 proxyauthenticationrequired
        0x48 requesttimeout
        0x49 conflict
        0x4a gone
        0x4b lengthrequired
        0x4c preconditionfailed
        0x4d requestedentitytoolarge
        0x4e requesturltoolarge
        0x4f unsupportedmediatype
        0x50 internalservererror
        0x51 notimplemented
        0x52 badgateway
        0x53 serviceunavailable
        0x54 gatewaytimeout
        0x55 httpversionnotsupported
        0x60 databasefull
        0x61 databaselocked
        0x7f protocolerror
    }
    proc ResponseCodeName {op} {
        variable ResponseCodeNames
        set op [expr {$op & 0x7f}]; # Knock off final bit
        set op [format 0x%2.2x $op]
        if {[info exists ResponseCodeNames($op)]} {
            return $ResponseCodeNames($op)
        }
        return response_$op
    }
    return [ResponseCodeName $op]
}

proc obex::core::response::ResponseCode {name} {
    variable ResponseCodeNames
    variable ResponseCodes

    ResponseCodeName 0x20 ;# Initialize the ResponseCodeNames array
    foreach {k v} [array get ResponseCodeNames] {
        set ResponseCodes($v) $k
    }

    proc ResponseCode {name} {
        variable ResponseCodes
        if {[info exists ResponseCodes($name)]} {
            return $ResponseCodes($name)
        }
        if {[string is integer -strict $name]} {
            return $name
        }
        error "Invalid response code \"$name\"."
    }

    return [ResponseCode $name]
}

proc obex::core::response::ResponseStatus {status} {
    set status [expr {$status & 0x7f}]
    if {$status < 0x10} {
        return protocolerror
    } elseif {$status < 0x20} {
        return informational
    } elseif {$status < 0x30} {
        return success
    } elseif {$status < 0x40} {
        return redirect
    } elseif {$status < 0x50} {
        return clienterror
    } elseif {$status < 0x60} {
        return servererror
    } elseif {$status < 0x70} {
        return databaseerror
    } else {
        return unknown
    }
}

proc obex::core::header::Id {name} {
    variable Ids
    # Initialize
    array set Ids {
        Count                  0xC0
        Name                   0x01
        Type                   0x42
        Length                 0xC3
        Timestamp              0x44
        Timestamp4             0xC4
        Description            0x05
        Target                 0x46
        Http                   0x47
        Body                   0x48
        EndOfBody              0x49
        Who                    0x4A
        ConnectionId           0xCB
        AppParameters          0x4C
        AuthChallenge          0x4D
        AuthResponse           0x4E
        CreatorId              0xCF
        WanUuid                0x50
        ObjectClass            0x51
        SessionParameters      0x52
        SessionSequenceNumber  0x93
    }
    # Redefine ourself to do actual work
    proc Id {name} {variable Ids; return $Ids($name)}
    return [Id $name]
}

proc obex::core::header::Name {hid} {
    variable Names

    # Initialize Names
    variable Ids
    Id Count;             #Just to ensure Ids initialized 
    foreach {name id} [array get Ids] {
        set Names($id) $name
    }

    # Redefine ourself to do actual work
    proc Name {hid} {
        variable Names
        set hid [format 0x%2.2X $hid]
        if {[info exists Names($hid)]} {
            return $Names($hid)
        }
        return $hid
    }
    return [Name $hid]
}

oo::class create obex::Helper {
    variable state; # Should be defined in containing class

    method headers {name} {
        # Retrieves the content of headers of a given type.
        #  name - name of the header
        # Returns a list each element of which is the value of a header
        #
        return [header findall $state(headers_in)]
    }

    method bodies {} {
        # Get the data content in a request or response
        #
        # The data content is transferred in Obex through headers of type `Body`
        # and `EndOfBody`. This method returns the values received through these
        # headers as a list. The content is in binary form and needs to be
        # appropriately interpreted depending on the application specifics. Note
        # the content may be fragmented at arbitrary boundaries during
        # transmission and so the returned values may need to be concatenated
        # before operations like UTF-8 decoding.
        #
        # Returns list of binary strings received through `Body` and `EndOfBody`
        # headers.

        set bodies {}
        foreach {name val} $state(headers_in) {
            if {$name in {Body EndOfBody}} {
                lappend bodies $val
            }
        }
        return $bodies
    }

    method OutgoingPacket {op is_response {extra_fields {}}} {
        # Constructs a outgoing packet from the queued outgoing headers.
        #  op - *numeric* request op or response status
        #  is_response - if true, this is a response packet, else a request
        #  extra_fields - binary data that goes after packet length field
        #        and before headers.
        # The returned packet includes as many headers as possible
        # from outgoing queue. The remaining are placed back
        # into queue.
        #
        # Should only be called for packets with "standard" 3 byte header
        # prefix.
        #
        # Returns a fully constructed Obex packet.

        # Get opcode+len occupies 3 bytes. And we need space for extra fields
        # extra_fields should not be more than 5 bytes and max_packet_size
        # is at least 255 so no bother checking for underflow
        set extra_len [string length $extra_fields]
        set space [expr {$state(max_packet_len)-3-$extra_len}]

        lassign [my PopHeaders $space] len headers
        set len [expr {$len+3+$extra_len}]

        if {$is_response} {
            # For ok, switch to continue if headers did not fit.
            if {[llength $state(headers_out)] != 0 && $op == 0xA0} {
                set op 0x90;    # "continue" op
            }
        } else {
            # If there are not more headers, set the final bit except in case of
            # streaming requests where data is passed in chunks.
            if {[llength $state(headers_out)] == 0 && ! $state(streaming)} {
                set op [expr {$op | 0x80}]; # FINAL bit
            }
        }
        append packet [binary format cuSu $op $len] $extra_fields {*}$headers
        return $packet
    }

    method PopHeaders {space} {
        set headers [list ]
        set total_len 0;        # Track total length of headers
        if {[info exists state(connection_header)]} {
            set hdrlen [string length $state(connection_header)]
            if {$space < $hdrlen} {
                # Should not happen
                error "No room for connection id header."
            }
            lappend headers $state(connection_header)
            set space [expr {$space - $hdrlen}]
            incr total_len $hdrlen
        }
        if {[llength $state(headers_out)] == 0} {
            return [list $total_len $headers]
        }
        # Add additional headers
        set i 0
        foreach header $state(headers_out) {
            set hdrlen [string length $header]
            if {$space < $hdrlen} {
                break
            }
            lappend headers $header
            incr i
            set space [expr {$space - $hdrlen}]
            incr total_len $hdrlen
        }

        if {$i == 0} {
            # Could not even fit one header other than connection id which
            # must be sent in every packet if present. This is bad.
            # TBD - how to report headers
            my RaiseError "A packet header exceeds connection packet size limit."
        }

        # Update state to reflect headers still to be sent.
        set state(headers_out) [lrange $state(headers_out) $i end]

        return [list $total_len $headers]
    }

    method SplitContent {content} {
        # Splits content into fragments based on maximum packet size.

        # Max length of a body excluding its header is
        # max packet size minus size of packet header (3) minus size of
        # connection id header (5) if any, minus size of body header (3)
        set fragment_len [expr {$state(max_packet_len) - 3 - 3}]
        if {[info exists state(connection_header)]} {
            set fragment_len [expr {$fragment_len - [string length $state(connection_header)]}]
        }
        set content_len [string length $content]
        set start 0
        set end [expr {$start + $fragment_len - 1}]
        set headers {}
        while {$start < $content_len} {
            lappend headers Body [string range $content $start $end]
            incr start $fragment_len
            incr end $fragment_len
        }
        return $headers
    }

    method AssertState {required_state} {
        if {$state(state) ne $required_state} {
            error "Method not allowed in state $state(state)."
        }
    }

    method AssertNotState {not_state} {
        if {$state(state) eq $not_state} {
            error "Method not allowed in state $not_state."
        }
    }

    method AssertOutgoingPacketLength {packet maxlen} {
        if {[string length $packet] > $maxlen} {
            my RaiseError "Outgoing packet length [string length $packet] exceeds max allowed packet length $maxlen."
        }
    }

    method SetErrorStatus {message} {
        set state(state) ERROR
        set state(error_message) $message
    }

}

oo::class create obex::Client {

    mixin obex::Helper

    # The Obex protocol only allows one request at a time. Accordingly,
    # a Client can be in one of the following states:
    #  IDLE - no request is outstanding.
    #  BUSY - a request is outstanding. state(request) indicates the request type.
    #  STREAMING - a request is still in progress, but server has responded
    #   and more data from application is awaited.
    #  ERROR - an error occurred on the conversation. Any request except abort
    #   will raise an exception.
    #
    # The state array contains the following keys:
    # Per connection:
    #  state - IDLE, BUSY, STREAMING, ERROR
    #  max_packet_len - max negotiated length of packet
    #  connection_id - ConnectionId as sent by remote. May not be present.
    #  connection_header - Binary connection header corresponding to $connection_id
    #  connected - a CONNECT request was successfully made. Note not all
    #   servers respond with a connection id so this does not mean the
    #   connection_id element is present.
    #  target - Target header sent, if any
    #  who    - Who header sent, if any
    # Per request:
    #  input - input buffer for received data
    #  op - current request operation
    #  headers_out - headers to send in current request in encoded binary form
    #  response - latest response
    #  headers_in - accumulated headers received in responses to request
    #  streaming - is a streaming request where content is provided piecemeal
    variable state

    constructor args {
        namespace path [linsert [namespace path] end ::obex ::obex::core]
        my reset
        if {[llength [self next]]} {
            next {*}$args
        }
    }

    method reset {} {
        # Resets state of the object.
        #
        # The object is placed in the same state as when it was newly constructed.
        # All state information is lost.

        # Connection specific state
        set state(state)  IDLE
        set state(connected) false
        unset -nocomplain state(connection_id)
        unset -nocomplain state(connection_header)
        unset -nocomplain state(target)
        unset -nocomplain state(who)
        set state(max_packet_len) 255; # Assume min unless remote tells otherwise

        # Request specific state
        my ResetRequest
    }

    method clear {} {
        # Clears error state if any.
        #
        # The object is restored to an idle state readying it for another
        # request. The command will raise an error if called while a request
        # is in progress.
        my ResetRequest
        set state(state) IDLE
        return
    }

    method input {data} {
        # Process data from the remote server.
        #   data - Binary data as received from remote server.
        # The method takes as input data received from the server as part of
        # the response to a request. The return value from the method is a list
        # of one or two elements. The first element is one of the following:
        #   `done`       - The full response has been received. The application
        #                  can then call any of the retrieval methods or initiate
        #                  another request. If the second element is present and
        #                  and not empty, it is data to be sent to the server.
        #                  The application can call other methods to retrieve
        #                  the result of the request. The application may also
        #                  call methods to initiate the next request.
        #   `continue`   - The response has only been partially received. If
        #                  the second element is present and not empty, it is
        #                  data to be sent to the server. In either case, the
        #                  application should read more data from the server
        #                  and invoke the `input` method again passing it the
        #                  read data.
        #   `writable`   - This value is only returned if the current operation
        #                  was a streaming `put` operation initiated with
        #                  [put_stream]. It indicates that [put_stream] should
        #                  be called again to send the next chunk of data.
        #   `failed`     - The request failed. See [Request completion status]
        #                  for dealing with errors and failures. If
        #                  the second element is present and not empty, it is
        #                  data to be sent to the server. In either case, the
        #                  application must not invoke additional requests
        #                  without first calling the [reset] method.
        #
        # This method will raise an exception if no request is currently
        # outstanding.
        #
        # Returns a list of one or two elements, the first being one of
        # `done`, `failed`, `continue` or `writable` and the second optional
        # element being data to send to the server.

        my AssertState BUSY

        # Append new data to existing
        append state(input) $data

        if {! [response decode $state(input) $state(op) response]} {
            return continue;    # Incomplete packet, need more input
        }

        # TBD - should this be a protocol error if input was longer than packet
        # Possibly a response followed by an ABORT?
        set state(input) [string range $state(input) [dict get $response PacketLength] end]

        # If we have a connection id, the incoming one must match if present
        if {[info exists connection_id]} {
            if {![header find $response(Headers) ConnectionId conn_id] ||
                $connection_id != $conn_id} {
                # TBD - ignore mismatches for now
            }
        }

        # Save as latest response
        set state(response) $response

        # For multipart responses, collect headers
        lappend state(headers_in) {*}[dict get $response Headers]

        # Do request-specific processing
        return [switch -exact -- $state(op) {
            connect    { my ConnectResponseHandler }
            disconnect { my ResponseHandler false }
            put        { my ResponseHandler true }
            get        { my ResponseHandler true }
            setpath    { my ResponseHandler false }
            session    { error "Internal error: session request."}
            abort      { my ResponseHandler false }
            default {
                error "Unexpected request opcode $state(op)."
            }
        }]
    }

    method await {chan action_state} {
        # Synchronously completes an ongoing operation.
        #  chan - A Tcl channel for communicating with the server. This
        #    must not be multiplexed with other requests.
        #  action_state - The return value from a method that returns
        #    an action state such as [connect], [disconnect], [get],
        #    [put], [put_delete], [put_stream], [setpath], [abort] or [input].
        #
        # The method places the passed channel into binary blocking mode and
        # uses it to communicate with the server to complete all remaining
        # steps required for the operation to complete. The original modes are
        # restored before returning.
        #
        # Returns `done`, `writable` or `failed`. See [input]. Note the
        # method will not return `continue`.

        set chan_config [chan configure $chan]
        chan configure $chan -blocking 1 -buffering none \
            -translation binary
        try {
            return [my Await $chan $action_state]
        } finally {
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

    method Await {chan action_state} {
        # Helper method for await.
        #
        # Implements the core of the [await] method but expects caller to
        # have configured the channel to be blocking, binary, unbuffered
        # and arranged to have the original configuration restored even
        # on error.
        lassign $action_state action data
        while {1} {
            if {[string length $data]} {
                # What if error? TBD
                puts -nonewline $chan $data
            }
            if {$action ne "continue"} {
                return $action
            }
            # Read the entire next packet.
            set packet [read $chan 3]
            if {[string length $packet] < 3} {
                my SetErrorStatus "Truncated read ([string length $packet]). Connection broken?"
                return failed
            }
            set packet_length [packet length $packet]
            if {$packet_length > 3} {
                # Read rest of packet
                set rest_len [expr {$packet_length - 3}]
                set rest [read $chan $rest_len]
                if {[string length $rest] < $rest_len} {
                    my SetErrorStatus "Truncated read ([string length $rest]). Connection broken?"
                    return failed
                }
                append packet $rest
            }
            lassign [my input $packet] action data
            # Loop back
        }

    }

    method state {} {
        # Returns the state of the client.
        #
        # The returned state is in the form of a dictionary with the following
        # elements:
        #   State - Client state; one of `IDLE`, `BUSY` or `ERROR`
        #   Connected - 0/1 depending on whether connected or not.
        #   ConnectionId - The connection id. Only present if connected
        #                  **and** remote server sent a connection id.
        #   MaxPacketLength - Maximum packet length negotiated.
        #   ErrorMessage - If present, the last error seen.

        set l [list State $state(state) \
                   Connected $state(connected) \
                   MaxPacketLength $state(max_packet_len)]
        
        if {[info exists state(connection_id)]} {
            lappend l ConnectionId $state(connection_id)
        }
        if {[info exists state(error_message)]} {
            lappend l ErrorMessage $state(error_message)
        }

        return $l
    }

    method response {} {
        # Returns the last response received from the server.
        #
        # The return value is a dictionary in the same form as returned by
        # the [::obex::core::response decode] command.
        return $state(response)
    }

    method idle {} {
        # Returns 1 if another request can be issued, otherwise 0.
        return [expr {$state eq "IDLE"}]
    }

    method connected {} {
        # Returns 1 if the client has an OBEX connection active.
        return $state(connected)
    }

    method status {} {
        # Returns the status of the last response received.
        #
        # The returned value is one of
        # `success`, `informational`, `redirect`,
        # `clienterror`, `servererror`, `databaseerror` or `protocolerror`.
        # See [::obex::Request completion status].
        #
        # The command will raise an error if no response has been received
        # for any request.
        return [dict get $state(response) ResponseStatus]
    }

    method status_detail {} {
        # Returns the detailed status of the last response received.
        #
        # The returned dictionary has the following keys:
        #  ResponseStatus   - The generic status category.
        #  ResponseCode     - The numeric response code from server.
        #  ResponseCodeName - Mnemonic form of `ResponseCode`
        #  ErrorMessage     - Additional human readable error status message. This
        #                     key may not be present.
        #
        # For more information on values for the above keys, see
        # [::obex::Request completion status].
        #
        # The command will raise an error if no response has been received
        # for any request.
        dict with state(response) {
            lappend status ResponseStatus $ResponseStatus \
                ResponseCode $ResponseCode \
                ResponseCodeName [response::ResponseCodeName $ResponseCode]
            if {[info exists state(error_message)]} {
                lappend status ErrorMessage $state(error_message)
            }
        }
        return $status
    }

    method connect {{headers {}}} {
        # Generates a Obex connect request.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if any are acceptable in `connect` request.
        # The following headers are commonly used in connects:
        # `Target`, `Who`, `Count`, `Length` and `Description`.
        #
        # The method should not be called multiple times without an
        # intervening call to [disconnect].
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        if {$state(connected)} {
            error "Already connected."
        }

        my BeginRequest connect
        set state(headers_out) [header encoden $headers]
        # Packet is opcode 0x80, 2 bytes length, version (1.0->0x10),
        # flags (0), 2 bytes max len (proposed)
        set extra [binary format cucuSu 0x10 0 65535]
        set packet [my OutgoingPacket 0x80 0 $extra]
        if {[llength $state(headers_out)]} {
            # Not all headers fit. Connect request must be a single packet
            my RaiseError "Headers too long for connect request."
        }
        return [list continue $packet]
    }

    method ConnectResponseHandler {} {
        dict with state(response) {
            if {$ResponseCode == 0xA0} {
                set state(connected) true
                # Store connection id if it exists
                if {[header find $Headers ConnectionId state(connection_id)]} {
                    set state(connection_header) \
                        [header encode ConnectionId $state(connection_id)]
                }
                # On init we assume worst case of 255 byte packets. If
                # remote is willing to go higher, use that.
                if {$MaxLength > 255} {
                    set state(max_packet_len) $MaxLength
                }
                # TBD - all other headers - Target, Who, Authentication etc.
            }
        }
        set state(state) IDLE
        return done;            # Means completed, not success
    }

    method disconnect {{headers {}}} {
        # Generates a Obex disconnect request.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if valid for `disconnect` requests.
        # The `ConnectionId` header is automatically generated as needed
        # and shoould not be included by the caller.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        if {!$state(connected)} {
            error "Not connected."
        }
        my BeginRequest disconnect
        set state(headers_out) [header encoden $headers]
        set packet [my OutgoingPacket 0x81 0]
        # Check if all headers were accomodated
        if {[llength $state(headers_out)]} {
            # Not all headers fit. Disconnect request must be a single packet
            my RaiseError "Headers too long for disconnect request."
        }
        set state(connected) false
        return [list continue $packet]
    }

    method put {content {headers {}}} {
        # Generates a Obex `PUT` request.
        #  content - Content to be sent to server as-is. This must be formatted
        #   appropriately based on the `Type` header, `Http` or `ObjectClass`
        #   headers passed in. If none of these are present,
        #   the server may interpret $content in any
        #   manner it chooses, possibly looking at the `Name` header if present,
        #   some default handling or even rejecting the request.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if any are acceptable in `put` request.
        # The following headers are commonly used in put operations:
        # `Name`, `Type`, `Http`, `Timestamp` and `Description`.
        # The headers `Body`, `EndOfBody`, `Length` and `ConnectionId`
        # are automatically generated and should not be passed in.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        # TBD - maybe break up content into body headers assuming body space
        #  is packet size - packet header - connection id header. That would
        # simplify Put method

        my BeginRequest put
        lappend headers Length [string length $content] {*}[my SplitContent $content]
        set state(headers_out) [header encoden $headers]
        return [list continue [my OutgoingPacket 0x02 0]]
    }

    method put_delete {{headers {}}} {
        # Generates a Obex `PUT` request to delete an object.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if any are acceptable in `put` request.
        # The following headers are commonly used in put operations:
        # `Name`, `Type`, `Http`, `Timestamp` and `Description`.
        # The headers `Body`, `EndOfBody`, `Length` should not be present
        # in a delete operation and should not be passed in. Moreover,
        # `ConnectionId` header is automatically generated and should not
        # be passed in.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        my BeginRequest put
        set state(headers_out) [header encoden $headers]
        return [list continue [my OutgoingPacket 0x02 0]]
    }

    method put_stream {chunk {headers {}}} {
        # Generates a Obex `PUT` request with content provided in chunks.
        #  chunk - A content chunk to be sent. An empty string indicates end
        #   of the stream. This must be formatted
        #   appropriately based on the `Type` header, `Http` or `ObjectClass`
        #   headers passed in the initial call to `put_stream`.
        #   If none of these are present,
        #   the server may interpret content in any
        #   manner it chooses, possibly looking at the `Name` header if present,
        #   some default handling or even rejecting the request.
        #  headers - List of alternating header names and values. Should
        #   be empty on all calls except the first.
        #
        # This is similar to the [put] method except that it permits the
        # caller to present the data to be sent in chunks instead of all at
        # once. The application provides each chunk of the content in repeated
        # calls to `put_stream`.
        # This is more memory-efficient for large files. Only the first
        # call initiating the `PUT` operation may specify headers. Passing
        # an empty string indicates end of the content.
        #
        # Streaming operation is achieved through the following sequence of
        # calls:
        #
        #  * Streaming is initiated through a call to `put_stream` which
        #    normally returns `continue` with data to send to the server.
        #  * The [input] method is called with the response from the server.
        #    This returns `writable` indicating more data can be sent. The
        #    application then calls `put_stream` again with the next chunk.
        #  * This `input`, `put_stream` sequence is repeated until there
        #    is no more data to send at which time the application should
        #    call `put_stream` with an empty chunk.
        # 
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if any are acceptable in `put` request.
        # The following headers are commonly used in put operations:
        # `Name`, `Type`, `Http`, `Timestamp` and `Description`.
        # The headers `Body`, `EndOfBody`, and `ConnectionId`
        # are automatically generated and should not be passed in.
        # This method does not automatically add a `Length` header since
        # the length is not known a priori. However, some server implementations
        # require the `Length` header and therefore should be passed in
        # as part of $headers in such cases.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.
        if {$state(state) eq "IDLE"} {
            my BeginRequest put
        } else {
            my AssertState STREAMING
            if {[llength $headers] != 0} {
                my RaiseError "Headers only allowed in first chunk of a data stream."
            }
        }
        if {[string length $chunk] != 0} {
            # Note no Length header as unknown!
            lappend headers {*}[my SplitContent $chunk]
            set state(streaming) 1
        } else {
            lappend headers EndOfBody {}
            set state(streaming) 0
            # TBD - do we need to guard against more put_stream calls
            # after EndOfBody is sent?
        }
        set state(headers_out) [header encoden $headers]
        set state(state) BUSY
        return [list continue [my OutgoingPacket 0x02 0]]
    }

    method get {{headers {}}} {
        # Generates a Obex `GET` request.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if any are acceptable in `put` request.
        # The following headers are commonly used in put operations:
        # `Name`, `Type`, `Http`, `Timestamp` and `Description`.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        my BeginRequest get
        set state(headers_out) [header encoden $headers]
        return [list continue [my OutgoingPacket 0x03 0]]
    }

    method abort {{headers {}}} {
        # Generates a Obex `ABORT` request.
        #  headers - List of alternating header names and values.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if valid for `ABORT` requests.
        # The `ConnectionId` header is automatically generated as needed
        # and should not be included by the caller.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        my BeginRequest abort
        set state(headers_out) [header encoden $headers]
        set packet [my OutgoingPacket 0xff 0]
        # Check if all headers were accomodated
        if {[llength $state(headers_out)]} {
            # Not all headers fit. Abort request must be a single packet
            my RaiseError "Headers too long for abort request."
        }
        return [list continue $packet]
    }

    method setpath {{headers {}} args} {
        # Generates a Obex `SETPATH` request.
        #  headers   - List of alternating header names and values.
        #  -parent   - Apply operation at the parent's level.
        #  -nocreate - Do no create folder if it does not exist.
        #
        # It is the caller's responsibility to ensure the value associated
        # with the header is formatted as described in [OBEX headers] and
        # that the supplied headers if valid for `SETPATH` requests.
        # The `ConnectionId` header is automatically generated as needed
        # and shoould not be included by the caller.
        #
        # Returns a list of one or two elements, the first of which is either
        # `continue` or `failed`, and the second, if present, is data to be sent
        # to the server. See [input] for details.

        my BeginRequest setpath

        set flags 0
        set constants 0
        foreach opt $args {
            switch -exact -- $opt {
                -parent { set flags [expr {$flags | 1}] }
                -nocreate { set flags [expr {$flags | 2}] }
                default {
                    error "Unknown option \"$opt\"."
                }
            }
        }

        set state(headers_out) [header encoden $headers]
        set packet [my OutgoingPacket 0x85 0 [binary format cucu $flags $constants]]
        if {[llength $state(headers_out)]} {
            # Not all headers fit. setpath request must be a single packet
            my RaiseError "Headers too long for setpath request."
        }
        return [list continue $packet]
    }

    method session {{headers {}}} {
        # Generate a OBEX `session` request.
        #  headers   - List of alternating header names and values.
        # This command is not implemented.
        error "Sessions not implemented in this release."
    }

    method ResponseHandler {continue_allowed} {
        set status_code [dict get $state(response) ResponseCode]
        if {$status_code == 0x90} {
            # CONTINUE
            # Send the next packet in the request
            if {$continue_allowed} {
                if {[llength $state(headers_out)] || ! $state(streaming)} {
                    return [list continue [my OutgoingPacket [request::OpCode $state(op)] 0]]
                } else {
                    # We have no more headers to send but are in streaming mode
                    # so application needs to give us something to send.
                    set state(state) STREAMING
                    return writable
                }
            } else {
                my SetErrorStatus "CONTINUE packet received for $state(op) request."
                return failed
            }
        } else {
            # If the final bit is not set, what does it mean? Do we continue
            # to wait for more data from server. In Obex 1.0, it is supposed
            # to be always set in response packets. So we treat as protocol
            # error if it is not.
            if {$status_code & 0x80} {
                # Note this does not mean success.
                set state(state) IDLE
                return done
            } else {
                my SetErrorStatus "FINAL bit not set in server response."
                return failed
            }
        }
    }

    method ResetRequest {} {
        set state(op) ""
        set state(input) ""
        set state(headers_out) {}
        set state(headers_in) {}
        set state(streaming) 0
        unset -nocomplain state(response)
    }

    method BeginRequest {op} {
        my AssertState IDLE
        my ResetRequest
        set state(op) $op
        set state(state) BUSY
    }

    method RaiseError {message} {
        my SetErrorStatus $message
        set status_detail [my status_detail]
        if {[dict exists $status_detail ErrorMessage]} {
            set detail [dict get $status_detail ErrorMessage]
            if {$detail ne $message} {
                append message " " [dict get $status_detail ErrorMessage]
            }
        } else {
            dict set status_detail ErrorMessage $message
        }
        return -level 1 -code error $message \
            -errorcode [list OBEX CLIENT $status_detail]
    }
}

oo::class create obex::Server {
    mixin obex::Helper

    # The Obex protocol only allows one request at a time. Accordingly,
    # a Server can be in one of the following states:
    #  IDLE - no request is outstanding.
    #  BUSY - a request is outstanding. state(op) indicates the request type.
    #  ERROR - an error occurred on the conversation.i
    #
    # The state array contains the following keys:
    # Per connection:
    #  state - IDLE, BUSY, ERROR
    #  max_packet_len - max negotiated length of packet
    #  connection_id - ConnectionId generated for this connection.
    #  connection_header - Binary connection header corresponding to $connection_id
    # Per request:
    #  input - input buffer for received data
    #  request - incoming decoded request
    #  headers_in - accumulated headers received in decoded form
    #  headers_out - binary response headers to send back to client
    variable state

    constructor args {
        namespace path [linsert [namespace path] end ::obex ::obex::core]
        my reset
        if {[llength [self next]]} {
            next {*}$args
        }
    }

    method input {data} {
        # Process data received from a client.
        #   data - Binary data as received from client.
        # The method takes as input data received from a client.
        # The return value from the method is a list of one or two
        # of one or two elements. The first element is one of `done`
        # `continue` or `failed`. The semantics depend on whether
        # the request is in the **request** phase or the **response**
        # phase.
        #
        # In the **request** phase,
        #   `done`  - The request was completed without need for an explicit
        #            response from the application. If the
        #            the second element is present and not empty, it is data
        #            to be sent to the client.
        #   `respond` - The full request has been received. The application should
        #            then call one of the response methods to reply to the client. If
        #            the second element is present and not empty, it is data
        #            to be sent to the client. The application can call other
        #            methods to retrieve the request.
        #   `continue` - The request has only been partially received. If the
        #            second element is present and not empty, it is data to be
        #            sent to the client. In either case, the application should
        #            read more data from the client and again invoke the [input]
        #            method passing it the read data.
        #   `failed` - The request has failed. See [Request completion status] for dealing
        #            with errors and failures. If the second element is present
        #            and not empty, it is data to be sent to the client. In
        #            either case, the application must not use this instance
        #            to accept additional requests without first calling the
        #            [reset] method.
        #
        # In the **response** phase,
        #   `done` - The full response has been sent to the client.
        #            If the second element is present and not empty, it is data
        #            to be sent to the client. The application can then
        #            process a new request using this object.
        #   `continue` - The response has only been partially sent. If the
        #            second element is present and not empty, it is data to be
        #            sent to the client. In either case, the application should
        #            read more data from the client and invoke the [input] method
        #            again passing it the read data.
        #   `failed` - The request has failed. See [Request completion status] for dealing
        #            with errors and failures. If the second element is present
        #            and not empty, it is data to be sent to the client. In
        #            either case, the application must not use this instance
        #            to accept additional requests without first calling the
        #            [reset] method.
        #

        switch -exact -- $state(state) {
            IDLE -
            REQUEST { my RequestPhaseInput $data}
            RESPOND { my ResponsePhaseInput $data}
            ERROR   { error "Method must not be called after an error without calling the reset method first."}
            default { error "Internal error: unknown state $state(state)"}
        }
    }

    method get_request {} {
        return $state(request)
    }

    method RequestPhaseInput {data} {

        # Append new data to existing
        append state(input) $data

        if {! [request decode $state(input) state(request)]} {
            return continue;    # Incomplete packet, need more input
        }

        dict with state(request) {}

        # TBD - protocol error if request code is not same as the in-progress one if any

        # TBD - should this be a protocol error if input was longer than packet
        # Possibly a response followed by an ABORT?
        # TBD - also means after sending response, app should call accept
        # again with an empty string as input.
        set state(input) [string range $state(input) $Length end]

        # If we have a connection id, the incoming one must match if present
        if {[info exists connection_id]} {
            if {![header find $Headers ConnectionId conn_id] ||
                $connection_id != $conn_id} {
                # TBD - ignore mismatches for now
            }
        }

        # For multipart requests, collect headers
        lappend state(headers_in) {*}$Headers

        if {$Final} {
            set state(state) RESPOND
            return $OpName
        } else {
            # Send back a continue 0x90 and wait for next packet
            set state(headers_out) {}
            return [list continue [my OutgoingPacket 0x90 1]]
        }
    }

    method ResponsePhaseInput {data} {
        append state(input) $data
        # In RESPONSE phase, we get requests with same type as ongoing
        # request or an ABORT
        if {![request decode $state(input) request]} {
            return continue
        }
        dict with request {}

        # TBD - note any headers are ignored. Process them? Raise error?
        if {$OpCode == [dict get $state(request) OpCode]} {
            set packet [my OutgoingPacket $state(response_code) 1]
            if {[llength $state(headers_out)]} {
                return [list continue $packet]
            } else {
                return [list done $packet]
            }
        } elseif {$OpCode == 0xFF} {
            # TBD - aborted
            set state(state) ERROR
            return failed
        } else {
            #TBD - protocol error
            set state(state) ERROR
            return failed
        }
    }

    method respond {status {headers {}}} {
        my AssertState RESPOND

        set state(headers_out) [header encoden $headers]
        set status [response::ResponseCode $status]
        set state(response_code) $status

        # CONNECT and DISCONNECT need special handling.
        set op [dict get $state(request) OpName]
        if {$op eq "connect"} {
            set state(max_packet_len) [dict get $state(request) MaxLength]
            set state(connection_id) [GenerateId]
            set state(connection_header) \
                [header encode ConnectionId $state(connection_id)]
            set state(headers_out) $headers
            # Packet is opcode 0x80, 2 bytes length, version (1.0->0x10),
            # flags (0), 2 bytes max len
            set extra_fields [binary format cucuSu 0x10 0 $state(max_packet_len)]
        } elseif {$op eq "disconnect"} {
            set extra_fields ""
            unset -nocomplain state(connection_id)
            unset -nocomplain state(connection_header)
            set state(max_packet_len) 255
        } else {
            set extra_fields ""
        }

        # TBD - assume a single packet response
        set status [expr {$status | 0x80}]
        set packet [my OutgoingPacket $status 1 $extra_fields]
        if {[llength $state(headers_out)]} {
            # TBD - don't know exactly how multipacket responses work when
            # status is not continue.
            my RaiseError "Response does not fit in a packet."
        }
        return [list done $packet]
    }

    method respond_content {content {headers {}}} {
        # Generate a response containing content.
        #  content - content to include in the response to the client.
        #  headers - List of alternating header names and values.
        #
        my AssertState RESPOND
        lappend headers Length [string length $content] {*}[my SplitContent $content]
        set state(headers_out) [header encoden $headers]
        set state(response_code) $status
        set packet [my OutgoingPacket $state(response_code) 1]
        if {[llength $state(headers_out)]} {
            return [list continue $packet]
        } else {
            return [list done $packet]
        }
    }

    method state {} {
        # Returns the state of the server.
        #
        # The returned state is in the form of a dictionary with the following
        # elements:
        #   State - Server state; one of `IDLE`, `REQUEST`, `RESPOND` or `ERROR`
        #   Connected - 0/1 depending on whether connected or not.
        #   ConnectionId - The connection id. Only present if connected.
        #   MaxPacketLength - Maximum packet length negotiated.
        #   ErrorMessage - If present, the last error seen.

        set l [list State $state(state) \
                   MaxPacketLength $state(max_packet_len)]
        if {[info exists state(connection_id)]} {
            lappend l Connected 1 ConnectionId $state(connection_id)
        } else {
            lappend l Connected 0
        }
        if {[info exists state(error_message)]} {
            lappend l ErrorMessage $state(error_message)
        }
        return $l
    }

    method reset {} {
        # Resets state of the object.
        #
        # The object is placed in the same state as when it was newly constructed.
        # All state information is lost.

        # Connection specific state
        set state(state)  IDLE
        unset -nocomplain state(connection_id); # Set when connect comes in
        unset -nocomplain state(connection_header)
        set state(max_packet_len) 255; # Assume min until remote tells otherwise

        # Request specific state
        my ResetRequest
    }

    method ResetRequest {} {
        unset -nocomplain state(request)
        unset -nocomplain state(response_code)
        set state(input) ""
        set state(headers_out) {}
        set state(headers_in) {}
    }

    method RaiseError {message} {
        # TBD - provide some detail as in status_detail for client
        my SetErrorStatus $message
        return -level 1 -code error $message \ 
            -errorcode [list OBEX CLIENT $message]
    }
}

namespace eval obex::private {
    proc find_target_install_dir {} {
        foreach tmdir [::tcl::tm::path list] {
            if {[file tail $tmdir] eq "8.6"} {
                return $tmdir
            }
        }
        return ""
    }
}

# Check if running as a tm
if {$::obex::is_module} {
    # Running as a tm. Provide an install command
    proc obex::private::install {{dir {}}} {
        if {$dir eq ""} {
            # Locate a directory on the module search path for Tcl 8.6
            set dir [find_target_install_dir]
            if {$dir eq ""} {
                error "Could not locate path for installing obex module."
            }
        }
        file copy -force [file join $::obex::dir $::obex::script] $dir
    }
    proc obex::private::distribute {{dir {}}} {
        error "Command distribute not available in module build."
    }
} else {
    # Not a tm, source the other files
    apply {{files} {
        foreach file $files {
            source [file join $obex::dir opp.tcl]
        }
    }} $obex::other_scripts

    proc obex::private::install {{dir {}}} {
        # Install directly from sources
        if {$dir eq ""} {
            # Locate a directory on the module search path for Tcl 8.6
            set dir [find_target_install_dir]
            if {$dir eq ""} {
                error "Could not locate path for installing obex module."
            }
        }
        distribute $dir
    }

    # Also define a distribute proc to generate a tm
    proc obex::private::distribute {{dir {}}} {
        if {$dir eq ""} {
            set dir [file join $::obex::dir .. dist]
        }
        set outname obex-$::obex::version
        set tmfile [file join $dir ${outname}.tm]

        file mkdir $dir
        set tm [open $tmfile w]

        foreach file [linsert $::obex::other_scripts 0 $::obex::script] {
            puts $tm "# File $file"
            set in [open [file join $::obex::dir $file] r]
            puts $tm [read $in]
            close $in
        }
    }
}

proc obex::private::uninstall {{ver {}}} {
    if {$ver eq "all"} {
        foreach dir [tcl::tm::path list] {
            foreach file [glob -nocomplain -directory $dir -- obex-*.tm] {
                if {[file exists $file]} {
                    puts "Uninstalling $file"
                    file delete $file
                }
            }
        }
    } else {
        if {$ver eq ""} {
            set ver $::obex::version
        }
        foreach dir [tcl::tm::path list] {
            set file [file join $dir obex-$ver.tm]
            if {[file exists $file]} {
                puts "Uninstalling $file"
                file delete $file
            }
        }
    }
}

package provide obex $obex::version



# If we are the main script, accept commands.
if {[info exists argv0] &&
    [file dirname [file normalize [info script]/...nosuchfile]] eq [file dirname [file normalize $argv0/...nosuchfile]]} {
    switch -exact -- [lindex $argv 0] {
        install {
            obex::private::install {*}[lrange $argv 1 end]
        }
        uninstall {
            obex::private::uninstall {*}[lrange $argv 1 end]
        }
        distribute {
            obex::private::distribute {*}[lrange $argv 1 end]
        }
        default {
            puts "Unknown command \"[lindex $argv 0]\"."
        }
    }
}
