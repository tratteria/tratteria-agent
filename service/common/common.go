package common

import "net/http"

type HttpMethod string

const (
	Get     HttpMethod = http.MethodGet
	Post    HttpMethod = http.MethodPost
	Put     HttpMethod = http.MethodPut
	Delete  HttpMethod = http.MethodDelete
	Patch   HttpMethod = http.MethodPatch
	Options HttpMethod = http.MethodOptions
)

var HttpMethodList = []HttpMethod{Get, Post, Put, Delete, Patch, Options}
