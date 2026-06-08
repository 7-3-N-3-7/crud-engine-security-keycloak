# Keycloak Security Module Architecture (Mermaid)

This file contains Mermaid diagrams visualizing the structure and design of the Keycloak security integration module (`crud-engine-security-keycloak`).

## 1. Class Structure

```mermaid
classDiagram
    class WebFilter {
        <<interface>>
        +filter(ServerWebExchange, WebFilterChain) Mono
    }

    class ReactiveJwtFilter {
        -String jwkSetUri
        -String testPublicKeyPem
        -CrudEngine crudManager
        -Map~String, PublicKey~ jwkCache
        +filter(ServerWebExchange, WebFilterChain) Mono
        -getVerificationKey(String) PublicKey
        -fetchJwks() void
        -getResourceName(String) String
    }

    class SecurityConfig {
        +securityWebFilterChain(ServerHttpSecurity) SecurityWebFilterChain
    }

    class SecurityAuditorAware {
        +getCurrentAuditor() Mono
    }

    ReactiveJwtFilter ..|> WebFilter : implements
```

## 2. JWT Verification and RBAC Flow

```mermaid
graph TD
    A[Incoming Request] --> B{Is public route?}
    B -- Yes --> C[Pass through chain]
    B -- No --> D{Authorization header exists?}
    D -- No --> E[Return 401 Unauthorized]
    D -- Yes --> F[Extract token]
    F --> G{Public Key cached?}
    G -- No --> H[Fetch keys from JWKS Endpoint]
    H --> I[Store key in cache]
    I --> J[Verify JWT Signature]
    G -- Yes --> J
    J --> K[Extract Tenant ID, Username, and Roles]
    K --> L[Look up Resource Metadata roles]
    L --> M{User has allowed role?}
    M -- No --> N[Return 403 Forbidden]
    M -- Yes --> O[Write tenantId & auth to context]
    O --> P[Pass request downstream]
```
