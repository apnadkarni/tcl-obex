# This file contains code to generate the documentation for the obex package.
# Usage:   tclsh doc.tcl

package require ruff
source [file join [file dirname [info script]] .. lib obex.tcl]

namespace eval obex {

    variable _preamble {

        ## The OBEX standard

        The Object Exchange (OBEX) standard defines a protocol and application
        framework for transferring objects and related meta-information between
        two devices. It is similar to HTTP in functionality except that it is
        geared towards smaller devices with more constrained resources.
        Originally designed for use over IrDA, it is now used over other
        transport protocols as well, in particular Bluetooth and TCP/IP.

        ## The `obex` package

        The `obex` package implements the OBEX protocol. It
        package may be downloaded from
        <https://sourceforge.net/projects/magicsplat/files/obex/>.
        After extracting into a directory listed in Tcl's `auto_path`,
        it can be loaded as

            package require obex

        Only OBEX client functionality is implemented in this release.

        The package is broken up into the following namespaces based on
        [OBEX profiles]:

        [::obex] - Implements the *Generic Object Exchange Profile* on which
                   the other profiles are based.
        [::obex::opp]  - Implements the *Object Push Profile*.
        [::obex::pbap] - Implements the *Phone Book Access Profile*.
                         (Well, at some point in the future.)
        [::obex::map]  - Implements the *Message Access Profile*.
                         (Coming up, right after PBAP!)
        [::obex::core] - Implements core low-level protocol commands.

        It is intended that details of the OBEX protocol is not
        required to use the `obex` package but some basic knowledge is useful.
        The sections below provide an overview.

        ## The OBEX protocol

        The OBEX session protocol is a client-server protocol where the
        client sends a request to a server which then sends a response
        back to the client. **The protocol only permits one request to be
        outstanding at a time.** Of course, independent requests may
        be in progress on separate transport connections.

        ## OBEX requests

        Each request is composed of multiple request packets based on the
        maximum packet size supported by the two ends of the OBEX conversation.

        A request packet begins with a *operation code*, or
        *opcode*, which specifies the requested operation, followed by a
        length field containing the length of the packet. These fixed fields
        are followed by optional *headers* which contain the attributes and data
        describing the desired operation. All request packets making up a single
        request start with the same operation code. The last packet in the
        request is marked by a special *final* bit which indicates the request
        is complete.

        The request opcodes have corresponding methods defined in the
        package. These are described in
        [OBEX operations][::obex::OBEX operations].

        The actual content itself, along with any metadata, is transferred
        in OBEX as a sequence of *[headers][OBEX headers]*,
        possible across multiple packets.

        ## OBEX responses

        Like requests, responses may be broken up into multiple response
        packets. A response packet has a similar structure to request packets
        except that the leading byte is a response code as opposed to a request
        opcode. These response codes are analogous to HTTP status codes and map
        to request completion status values as described in
        [Request completion status].

        Just like for requests, the data and related information in responses
        is transferred in the form of [headers][OBEX headers].

        ## OBEX profiles

        A *profile* defines

        * An application usage scenario in terms of the functionality exposed
        to the user.
        * The requirements expected of the underlying protocol stacks to
        ensure interoperability.
        * The message formats and operations used to exchange
        objects between application instances.

        Two independently developed applications adhering to the same profile
        are assured of interoperability.

        As an example, consider the *Bluetooth Phone Book Access Profile
        (PBAP)*. The usage scenario for the profile is retrieval of phone book
        entries stored on a *server* device from a *client* device. The protocol
        requirements include OBEX over RFCOMM over L2CAP as the transport with
        SDP for service advertising. The operations include GET/PUT for
        retrieval of the phone book as well as individual entries. Message
        formats include use of specific OBEX headers and formats specific
        to the content (e.g. v-card).

        In the `obex` package, profiles are implemented within namespace that
        reflect the profile name. For example, the client and server classes
        for the *Object Push Profile (OPP)* are contained in the `::obex::opp`
        namespace.
    }
}

namespace eval obex {
    variable _ruff_preamble {

        The `obex` namespace contains the [Client] and [Server] classes which
        implement the `Generic Object Exchange Profile (GOEP)` on which all
        other OBEX profiles are based. These classes may be used to access or
        provide any OBEX based service but require the application to have more
        knowledge of the profile with which that service is compliant. The
        profile-specific classes are easier to use in that regard.

        [Client] - Implements GOEP client functionality.
        [Server] - Implements GOEP server functionality.

        ## OBEX operations

        An OBEX operation consists of the client making one of the
        requests in the table below by calling the method of the same name.
        This is the request phase during which multiple packets may be
        exchanged with the server. The exchange then enters the response
        phase in which the server responds to the request via another
        multiple packet exchange. A single request may be in progress
        on a single transport connection at a time.

        `connect` - Initiate a conversation and establish context.
        `disconnect` - Terminate a conversation.
        `put`     - Send an object to the server.
        `get`     - Retrieve an object from the server.
        `setpath` - Sets the object directory location on the server.
        `session` - Used for reliable session support over unreliable
                    transports. Not supported by the `obex` package.
        `abort`   - Special request sent to abort an ongoing request.

        The normal mode of operation consists of a sequence of requests
        starting with a `connect`, ending with a `disconnect`, and one or
        more of the other requests in between. Note that the `connect` and
        `disconnect` are optional for some some servers which will accept
        the `put` and `get` requests without a preceding `connect`.

        ## Packet transfer model

        The [OBEX session protocol](obex.html#The_OBEX_Session_protocol) allows
        for one request at a time. This one request may result in multiple
        packets in both directions that need to be processed for the request to
        be completed. Rather than carrying out this communications itself,
        the [Client] and [Server] objects depend on the application itself
        to do the actual packet transfer. This makes the implementation
        independent of the channels, whether synchronous or event-driven
        I/O is used and so on. For all it knows, the data is transferred
        by encapsulating in E-mail.

        ### Generating requests

        From the client side, a request to connect looks as below:

        ````
        obex::Client create Client
        lassign [client connect] step data
        while {$step eq "continue"} {
            if {[string length $data]} {
                ...send $data to server...
            }
            set reply [...get data from server..]
            lassign [client input $reply]
        }
        if {$step eq "done"} {
            # Operation completed. Check if successful.
            if {[client status] eq "success"} {
                ... handle success ...
            } else {
                ... handle error ...
            }
        } else {
            # assert $step == "failed". Operation could not be completed.
            ... Handle bad news ...
        }
        ````

        Although this fragment used the `connect` operation, the model
        is exactly the same for other operations such as `get`, `put` etc.
        All the methods that implement these operations return a pair
        consisting of the next step to take and optionally data to send
        to the server. The application then sends data, if any, to the
        server. Then if the step value was `continue`, application needs
        to read additional data and feed whatever it gets (at least one byte)
        to the [Client.input] method. This step is repeated as long
        as the `input` method returns `continue`. At any state, a method
        may return `done` indicating all communication is over and the
        request completed or `failed` indicated the request could not
        be completed. **Note that `done` only indicates the operation
        was completed, not that it was successful.** More on this in
        [Request completion status].

        The above illustrates the conceptual model but of course the application
        may choose to do the equivalent non-sequentially via the event loop and
        non-blocking I/O.

        ### Request completion status

        The completion of a request is indicated by a return value of
        `done`, `writable` or `failed` from the operation methods.

        The value `writable` is only returned in a `PUT` streaming operation
        to indicate the next chunk of the data stream may be sent. See
        [::obex::Client.put_stream] for details.

        The value `failed` indicates a complete response was not received from
        the server. The cause may be protocol version incompatibility, protocol
        errors, loss of connectivity and so on. 

        The value `done` indicates a full and valid response was received from
        the server. However, this does not mean that the request itself was
        successful as the server response may indicate failure or some
        other status. This status can be checked with the [Client.status]
        method which returns one of the following values:
        `success`, `informational`, `redirect`,
        `clienterror`, `servererror`, `databaseerror` or `protocolerror`.

        Each request completion status value corresponds to one of several OBEX
        response codes from the server. The actual response code may be obtained
        with the [Client.status_detail] method. The `ResponseCode` and
        `ResponseCodeName` dictionary keys returned by the method contain the
        numeric and mnemonic values.

        A status of `success` includes the following response codes
        (mnemonic values shown):

        `ok`               - Success.
        `created`          - Object was created.
        `accepted`         - Request accepted.
        `nonauthoritative` - Non-authoritative information.
        `nocontent`        - No content.
        `resetcontent`     - Reset content.
        `partialcontent`   - Partial content.

        A status of `informational` includes the following response codes:

        `continue` - Client should send next packet in the request.
                     This is internally handled by the package.

        A status of `redirect` includes the following response codes and
        indicates the resource or object is available elsewhere or by
        some other means.

        `multiplechoices`  - Multiple choices.
        `movedpermanently` - Moved permanently.
        `movedtemporarily` - Moved temporarily.
        `seeother`         - See other.
        `notmodified`      - Not modified.
        `useproxy`         - Use proxy.

        A status of `protocolerror` includes the following response codes:

        `protocolerror` - Generated internally by the `obex` package
                        if a protocol error occured. It does not actually map
                        to a OBEX response.

        A status of `clienterror` indicates an error by the client in
        its request. It includes the following response codes:

        `badrequest`       - Bad request. Server could not understand request.
        `unauthorized`     - Unauthorized.
        `paymentrequired`  - Payment required.
        `forbidden`        - Forbidden. Request understood but denied.
        `notfound`         - Not found.
        `methodnotallowed` - Method not allowed.
        `notacceptable`    - Request not acceptable.
        `proxyauthenticationrequired` - Proxy authentication required.
        `requesttimeout`              - Request timed out.
        `conflict`                    - Conflict.
        `gone`                        - Gone.
        `lengthrequired`              - Length required.
        `preconditionfailed`          - Precondition failed.
        `requestedentitytoolarge`     - Requested entity too large.
        `requesturltoolarge`          - Request URL too large.
        `unsupportedmediatype`        - Unsupported media.

        A status of `servererror` indicates an error on the server in
        responding to a request and includes the following response codes:

        `internalservererror`         - Internal server error.
        `notimplemented`              - Not implemented.
        `badgateway`                  - Bad gateway.
        `serviceunavailable`          - Service unavailable.
        `gatewaytimeout`              - Gateway timed out.
        `httpversionnotsupported`     - Version not supported.

        A status of `databaseerror` includes the following response codes:

        `databasefull`                - Database full.
        `databaselocked`              - Database locked.


        ### Synchronous completion

        As a convenience most suitable for interactive use, the
        [Client.await] method can be used instead of the above idiom
        to synchronously wait for a request to complete. The equivalent
        of the above example would be

        ````
        set status [client await $chan [client connect]]
        if {$status eq "done"} {
            ...
        } else {
            ...
        }

        ````

        This runs the "continue" loop shown previously internally until the
        request succeeds or fails. The disadvantage of this method is that it
        will block the event loop until completion and offers no protection
        against timeouts, a non-responsive server and other such errors.

        ### Channel configuration

        OBEX is a binary protocol. Any channels used to pass data should
        therefore be configured to be in binary mode. Moreover, because
        OBEX packets are small and never have more than one outstanding,
        buffering should be turned off.

            chan configure $chan -translation binary -buffering none


        ### Generating responses

        [TBD]

        ### OBEX headers

        The actual object itself, and any related metadata about it,
        is transferred in OBEX packets as a sequence of *headers*.
        For example, in a file transfer using `get` operations, the
        request may contain a `Name` header specifying the requested file
        while the response would include `Body` and `Timestamp` headers
        containing the file content and time of creation respectively.

        The headers that allowed a OBEX conversation and the
        context in which they are used are defined by the
        [profile][OBEX profiles] followed by the application.

        A header consists of two parts:

        * The *header identifier* which specifies both the type and the
        semantics of the header.

        * The *header value* whose format is fully defined by the header
        identifier.

        Header values may be a string, a binary (sequence of bytes),
        a 8-bit value or a 32-bit value. When passing header values into
        `obex` commands, the caller has to ensure the value is formatted
        appropriately. For strings and integers, this is straightforward. For
        byte sequences, caller must ensure the value is generated as a binary
        using the `binary format` or `encoding convertto` commands, read
        from a binary channel and so on.

        The table below shows the header identifiers.

        AppParameters - Byte sequence. Used by layered applications to include
                        additional information in a request or response. The
                        value is a byte sequence of (tag,length,value) triples
                        where tag and length are one byte each. Tags and
                        semantics are defined by the application.

        AuthChallenge - Byte sequence. Authentication challenge.
        AuthResponse  - Byte sequence. Authentication response.
        Body          - Byte sequence. A chunk of the object content.
        ConnectionId  - 32-bit. The connection id used when multiplexing multiple
                        OBEX connections over one transport connection.
        Count         - 32-bit. Number of objects involved in the operation.
        CreatorId     - 32-bit. Unsigned integer that identifies the creator
                        of an object.
        Description   - String. Describes the object or provides additional
                        information about the operation, errors etc.
        EndOfBody     - Byte sequence. The last chunk of the object content.
        Http          - Byte sequence. This has the same format as HTTP 1.x
                        headers and should be parsed as HTTP headers with the
                        same semantics.
        Length        - 32-bit. Length of object in bytes.
        Name          - String. Name of the object, e.g. a file name.
        ObjectClass   - Byte sequence. Similar in function to the `Type` header
                        except the scope of the semantics are specific to the
                        layered application.
        SessionParameters - Byte sequence. Parameters in `session` commands.
        SessionSequenceNumber - 8-bit. Used for sequencing packets in a session.
        Target     - Byte sequence. Specifies the service to process a request.
                     Must be the first header in a request packet if present and
                     cannot be used together with the `ConnectionId` header
                     within a **request**.
        Timestamp  - Byte sequence. Represents time of last modification of the
                     object. This should be in ISO 8601 format as
                     `YYYYMMDDTHHMMSS` for local time and `YYYYMMDDTHHMMSSZ` for
                     UTC. Note this is a byte sequence and **not** a string.
        Timestamp4 - 32-bit. Represents time of last modification as number of
                     seconds since January 1, 1970.
        Type       - Byte sequence. Describes the type of the object in the same
                     manner as HTTP's `Content-Header` header. The value is a
                     byte sequence of ASCII characters terminated by a null,
                     **not** a string.
        WanUuid    - Byte sequence. Only used in stateless networks environments
                     where the OBEX server resides on network client with the
                     OBEX client residing on the network server. The OBEX server
                     (the network client) then includes this in all responses.
        Who        - Byte sequence. Similar to the `Target` header except
                     that while `Target` in a request identifies the desired
                     service, `Who` in a response identifies the service
                     generating the response.
    }
}

namespace eval obex::core {
    variable _ruff_preamble {

        The `obex::core` namespace contains the low level commands
        implementing the OBEX protocol. Their use is not recommended
        without detailed knowledge of the protocol. The classes and
        commands in the other `obex` namespaces should be used instead.

    }

}

proc obex::Document {outfile args} {
    # Generates documentation for the actor package
    #  outfile - name of output file
    #  args - additional arguments to be passed to `ruff::document`.
    # The documentation is generated in HTML format. The `ruff` 
    # documentation generation package must be installed.
    #
    # Warning: any existing file will be overwritten.
    variable _preamble

    set ns [namespace current]
    set namespaces [list $ns ${ns}::core]
    ruff::document $namespaces -autopunctuate 1 -excludeprocs {^[_A-Z]} \
        -excludeclasses [list ${ns}::Server] \
        -recurse 0 -preamble $_preamble -pagesplit namespace \
        -output $outfile -includesource 1 \
        -title "obex package reference (V[package present obex])" \
        {*}$args
}

if {[file normalize $argv0] eq [file normalize [info script]]} {
    cd [file dirname [info script]]
    obex::Document obex.html {*}$argv
}
