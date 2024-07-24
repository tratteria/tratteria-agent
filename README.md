# Tratteria Agent

Sidecar agents for verifying TraTs in microservices.

## How to Setup Tratteria Agent

Tratteria agents are injected into microservices pods to verify TraTs. To integrate tratteria agent into a microservice, follow these steps:

### Enable Tratteria in Namespace:

Make sure tratteria is enabled in your namespace. Add the following label to the namespace to enable tratteria:

```yaml
metadata:
  name: [your-namespace]
  labels:
      tratteria-enabled: "true"
```

### Add Tratteria Annotations in the Microservice Deployment Resource:

Include the below annotations in the microservice deployment resource:

```yaml
annotations:
  tratteria/inject-sidecar: "true" # Set this to true to inject the agent
  tratteria/service-port: "8090"  # The port your microservice uses for incoming requests
```

### Operating Modes

Tratteria agent can be configured to operate in two modes:

#### Interception Mode:

Tratteria agents intercept incoming requests, extract the TraT from the `Txn-Token` header, verify it, and forward the trat-verified request to the microservice.

To enable interception mode, set `enableTratInterception` to `true` in the [tconfig configuration](https://github.com/tratteria/tconfigd/tree/main/installation#3-configure-tconfigd).

#### Delegation Mode:

In this mode, incoming requests are not intercepted; instead, requests must be made to the agent’s endpoint for verifying a trat. The agent then responds with the verification result. This mode is suitable for environments where intercepting requests is not possible or desired, for example, in environments with a service mesh that is already intercepting incoming requests.

**Delegation Endpoint Details**

**Endpoint**: `POST /verify-trat`

This endpoint takes request data as input and responds with the result of the trat verification.

**Request Body**:

Structure:

```json
{
    "endpoint": "request URL path",
    "method": "request HTTP method",
    "body": "request JSON payload",
    "headers": "JSON object of request HTTP headers",
    "queryParameters": "JSON object of request URL query parameters"
}
```

Example:

```json
{
    "endpoint": "/order",
    "method": "POST",
    "body": {
        "stockID": 12345,
        "action": "buy",
        "quantity": 100
    },
    "headers": {
        "Content-Type": "application/json"
    },
    "queryParameters": {}
}
```


**Response Format**:

Valid trat response:

```json
{
  "valid": true
}
```

Invalid trat response:

```json
{
  "valid": false
}
```

To enable delegation mode, set `enableTratInterception` to `false` in the [tconfig configuration](https://github.com/tratteria/tconfigd/tree/main/installation#2-configure-tconfigd).

## Example Application
For a practical deployment example, check out the [example application deployment setup](https://github.com/tratteria/example-application/tree/main/deploy).

## Tratteria Documentation
For detailed documentation and setup guides of tratteria please visit tratteria official documentation page: [tratteria.io](https://tratteria.io)

## Contribute to Tratteria
Contributions to the project are welcome, including feature enhancements, bug fixes, and documentation improvements.