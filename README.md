# Tokenetes Agent

Sidecar agents for verifying TraTs (Transaction Tokens) in microservices.

## How to Setup Tokenetes Agent

Tokenetes agents are injected into microservices pods to verify TraTs. To integrate the Tokenetes agent into a microservice, follow these steps:

1. Enable Tokenetes in Your Namespace

    Make sure Tokenetes is enabled in your namespace. Add the following label to the namespace:

    ```yaml
    metadata:
      name: [your-namespace]
      labels:
          tokenetes-enabled: "true"
    ```

2. Add Tokenetes Annotations in the Microservice Deployment Resource

    Set the annotation `tokenetes/inject-sidecar` to `true` in a microservice deployment resource to inject the Tokenetes Agent into the microservice pods:

    ```yaml
    annotations:
      tokenetes/inject-sidecar: "true" # Controls agent injection: true to inject, false to skip
    ```

    Agents are configurable using annotations. Currently, the following annotations are supported:

    1. `tokenetes/agent-mode`: Specifies the mode for this particular microservice. This overrides the general agent-mode set in the [tconfig configuration](https://github.com/tokenetes/tconfigd/tree/main/installation#3-configure-tconfigd) for this microservice. Set to `delegation` for delegation mode or `interception` for interception mode.

    2. `tokenetes/service-port`: The port the microservice uses for incoming requests. This is required if the agent is running in interception mode and is not required for delegation mode.

### Operating Modes

Tokenetes agent can be configured to operate in two modes:

#### Interception Mode:

Tokenetes agents intercept incoming requests, extract the TraT from the `Txn-Token` header, verify it, and forward the trat-verified request to the microservice.

To enable interception mode, set `enableTratInterception` to `true` in the [tconfig configuration](https://github.com/tokenetes/tconfigd/tree/main/installation#3-configure-tconfigd). You can also specify it at the microservice level with the `tokenetes/agent-mode` annotation as mentioned above.

#### Delegation Mode:

In this mode, incoming requests are not intercepted; instead, requests must be made to the agent’s endpoint for verifying a trat. The agent then responds with the verification result. This mode is suitable for environments where intercepting requests is not possible or desired, for example, in environments with a service mesh that is already intercepting incoming requests.

**Delegation Endpoint Details**

**Endpoint**: `POST /verify-trat`

**Port**: The endpoint is available on the `agentApiPort` port configured in the [tconfig configuration](https://github.com/tokenetes/tconfigd/tree/main/installation#2-configure-tconfigd).

**Host**: `localhost` (The agent runs in the same pod as the microservice)

**Sample API Endpoint:** http://localhost:<agentApiPort>/verify-trat

For example, if `agentApiPort` is configured as `9030`, the full API endpoint would be: `POST http://localhost:9030/verify-trat`

This endpoint takes request data as input and responds with the result of the TraT verification.

**Request Body**:

Structure:

```json
{
    "path": "request URL path",
    "method": "request HTTP method",
    "body": "request JSON payload",
    "headers": "JSON object of request HTTP headers",
    "queryParameters": "JSON object of request URL query parameters"
}
```

Example:

```json
{
    "path": "/order",
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
  "valid": false,
  "reason": "invalid authorization details"
}
```

To enable delegation mode, set `enableTratInterception` to `false` in the [tconfig configuration](https://github.com/tokenetes/tconfigd/tree/main/installation#2-configure-tconfigd). You can also specify it at the microservice level with the `tokenetes/agent-mode` annotation as mentioned above.

For a reference implementation of Tokenetes Agents modes of TraT verification, check out the [example application](https://github.com/tokenetes/example-application). The stocks service uses the delegation method of TraT verification, while the order service uses the interception method of TraT verification.

## Example Application
For a practical deployment example, check out the [example application deployment setup](https://github.com/tokenetes/example-application/tree/main/deploy).

## Tokenetes Documentation
For detailed documentation and setup guides of tokenetes please visit tokenetes official documentation page: [tokenetes.io](https://tokenetes.io)

## Contribute to Tokenetes
Contributions to the project are welcome, including feature enhancements, bug fixes, and documentation improvements.