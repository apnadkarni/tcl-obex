# This file contains code to generate the documentation for the obex package.
# Usage:   tclsh doc.tcl

package require ruff
source [file join [file dirname [info script]] .. lib obex.tcl]

namespace eval obex {

    variable _preamble {

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
        [OBEX Profiles]:

        [::obex] - Implements the *Generic Object Exchange Profile* on which
                   the other profiles are based.
        [::obex::opp]  - Implements the *Object Push Profile*.
        [::obex::pbap] - Implements the *Phone Book Access Profile*.
        [::obex::map]  - Implements the *Message Access Profile*.
        [::obex::core] - Implements core low-level protocol commands.

        ## The OBEX Session protocol

        The OBEX session protocol is a client-server protocol where the
        client sends a request to a server which then sends a response
        back to the client. The protocol only permits one request to be
        outstanding at a time so the client is barred from sending a
        second request while a previous one is still in progress on
        that transport connection. Of course, independent requests may
        be in progress on separate transport connections.

        ### OBEX Requests

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

        #### OBEX Request opcodes

        The following table shows the possible request operations that
        a client may initiate:

        `connect` - Initiate a conversation and establish context. Note this is
                    not always necessary for data transfer.
        `disconnect` - Terminate a conversation. This clears the context but
                    does not mean further operations are not possible on the
                    underlying transport connection.
        `put`     - Send an object to the server.
        `get`     - Retrieve an object from the server.
        `setpath` - Sets the object directory location on the server.
        `session` - Used for reliable session support. Not supported by
                    the `obex` package.

        ### OBEX Responses

        Like requests, responses may be broken up into multiple response
        packets. A response packet has a similar structure to request packets
        except that the leading byte is a response code as opposed
        to a request opcode. These response codes are analogous to HTTP
        status codes.

        #### OBEX Response codes

        The possible response codes are categorized into a response status which
        may be one of the following: `success`, `informational`, `redirect`,
        `clienterror`, `servererror`, `databaseerror` or `protocolerror`.

        A status of `success` includes the following response codes:

        ok               - Success.
        created          - Object was created.
        accepted         - Request accepted.
        nonauthoritative - Non-authoratative information.
        nocontent        - No content.
        resetcontent     - Reset content.
        partialcontent   - Partial content.

        A status of `informational` includes the following response codes:

        continue         - Client should send next packet in the request.

        A status of `redirect` includes the following response codes and
        indicates the resource or object is available elsewhere or by
        some other means.

        multiplechoices  - Multiple choices.
        movedpermanently - Moved permanently.
        movedtemporarily - Moved temporarily.
        seeother         - See other.
        notmodified      - Not modified.
        useproxy         - Use proxy.

        A status of `protocolerror` includes the following response codes:

        protocolerror - Generated internally by the `obex` package
                        if a protocol error occured. It does not actually map
                        to a OBEX response.

        A status of `clienterror` indicates an error by the client in
        its request. It includes the following response codes:

        badrequest       - Bad request. Server could not understand request.
        unauthorized     - Unauthorized.
        paymentrequired  - Payment required.
        forbidden        - Forbidden. Request understood but denied.
        notfound         - Not found.
        methodnotallowed - Method not allowed.
        notacceptable    - Request not acceptable.
        proxyauthenticationrequired - Proxy authentication required.
        requesttimeout              - Request timed out.
        conflict                    - Conflict.
        gone                        - Gone.
        lengthrequired              - Length required.
        preconditionfailed          - Precondition failed.
        requestedentitytoolarge     - Requested entity too large.
        requesturltoolarge          - Request URL too large.
        unsupportedmediatype        - Unsupported media.

        A status of `servererror` indicates an error on the server in
        responding to a request and includes the following response codes:

        internalservererror         - Internal server error.
        notimplemented              - Not implemented.
        badgateway                  - Bad gateway.
        serviceunavailable          - Service unavailable.
        gatewaytimeout              - Gateway timed out.
        httpversionnotsupported     - Version not supported.

        A status of `databaseerror` includes the following response codes:

        databasefull                - Database full.
        databaselocked              - Database locked.

        ### OBEX Headers

        The actual object itself, and any related meta-information about it,
        is transferred in OBEX packets as a sequence of *headers*. A header
        consists of two parts:

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

        ## OBEX Profiles

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

        ## Data transfer model

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
            # Succeeded
            ...Proceed with next request...
        } else {
            # assert $step == "failed"
            ...Error or failure handling...
        }
        ````

        Although this fragment used the `connect` operation, the model
        is exactly the same for other operations such as `get`, `put` etc.
        All the methods that implement these operations return a pair
        consisting of the next step to take and optionally data to send
        to the server. The application then sends data, if any, to the
        server. Then if the step value was `continue`, application needs
        to read additional data and feed whatever it gets (at least one byte)
        to the [Client::input] method. This step is repeated as long
        as the `input` method returns `continue`. At any state, a method
        may return `done` indicating all communication is over and the
        request completed successfully or `failed` indicated the request
        completed with a failure.

        The above illustrates the conceptual model but of course the application
        may choose to do the equivalent non-sequentially via the event loop and
        non-blocking I/O.


        ### Synchronous completion

        ### Channel configuration

        ## OBEX operations

        ### Generating responses

        [TBD]

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
