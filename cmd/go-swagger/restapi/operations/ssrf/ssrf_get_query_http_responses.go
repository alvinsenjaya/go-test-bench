// Code generated by go-swagger; DO NOT EDIT.

package ssrf

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// SsrfGetQueryHTTPOKCode is the HTTP code returned for type SsrfGetQueryHTTPOK
const SsrfGetQueryHTTPOKCode int = 200

/*SsrfGetQueryHTTPOK returns the rendered response as a string

swagger:response ssrfGetQueryHttpOK
*/
type SsrfGetQueryHTTPOK struct {

	/*The response when succesful query happens
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewSsrfGetQueryHTTPOK creates SsrfGetQueryHTTPOK with default headers values
func NewSsrfGetQueryHTTPOK() *SsrfGetQueryHTTPOK {

	return &SsrfGetQueryHTTPOK{}
}

// WithPayload adds the payload to the ssrf get query Http o k response
func (o *SsrfGetQueryHTTPOK) WithPayload(payload string) *SsrfGetQueryHTTPOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the ssrf get query Http o k response
func (o *SsrfGetQueryHTTPOK) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SsrfGetQueryHTTPOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

/*SsrfGetQueryHTTPDefault Error occured

swagger:response ssrfGetQueryHttpDefault
*/
type SsrfGetQueryHTTPDefault struct {
	_statusCode int
}

// NewSsrfGetQueryHTTPDefault creates SsrfGetQueryHTTPDefault with default headers values
func NewSsrfGetQueryHTTPDefault(code int) *SsrfGetQueryHTTPDefault {
	if code <= 0 {
		code = 500
	}

	return &SsrfGetQueryHTTPDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the ssrf get query HTTP default response
func (o *SsrfGetQueryHTTPDefault) WithStatusCode(code int) *SsrfGetQueryHTTPDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the ssrf get query HTTP default response
func (o *SsrfGetQueryHTTPDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WriteResponse to the client
func (o *SsrfGetQueryHTTPDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(o._statusCode)
}