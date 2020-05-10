# This file contains code to generate the documentation for the obex package.

package require ruff
source [file join [file dirname [info script]] .. lib obex.tcl]

namespace eval obex {
    variable _preamble {

        ## Downloads

        The extension may be downloaded from
        <https://sourceforge.net/projects/magicsplat/files/obex/>.
    }
}

namespace eval obex {

    variable _ruff_preamble {

        The Object Exchange (OBEX) standard defines a protocol and application
        framework for transferring objects and related meta-information between
        two devices. It is similar to HTTP in functionality except that it is
        geared towards smaller devices with more constrained resources.
        Originally designed for use over IrDA, it is now used over other
        transport protocols as well, in particular Bluetooth and TCP/IP.

        The `obex` package implements the OBEX protocol. It can be loaded as

            package require obex

        Only OBEX client functionality is implemented in this release.

        ## The OBEX Session protocol

        The OBEX session protocol is a client-server protocol where the
        client sends a request to a server which then sends a response
        back to the client. The protocol only permits one request to be
        outstanding at a time so the client is barred from sending a
        second request while a previous one is still in progress on
        that transport connection. Of course, independent requests may
        be in progress on separate transport connections.

        ### Requests

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

        #### Request opcodes

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

        ### Responses

        Like requests, responses may be broken up into multiple response
        packets. A response packet has a similar structure to request packets
        except that the leading byte is a response code as opposed
        to a request opcode. These response codes are analogous to HTTP
        status codes.

        #### Response codes

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

        protocolerror    - Generated internally by the `obex`
        package if a protocol error occured. It does not actually map
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
    set namespaces [list $ns]
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
