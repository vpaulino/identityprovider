﻿# Introduction

A minimal Identity Provider built in ASP.NET Core to explore and understand OAuth2 and OpenID Connect flows, including Authorization Code and On-Behalf-Of. This project simulates how real IdPs work, focusing on protocol mechanics, token generation, scopes, audiences, and secure delegation. Ideal for hands-on learning and experimentation.

# OAuth 2.0 / OIDC Architecture with On-Behalf-Of Flow

This solution implements a multi-layer architecture using OAuth 2.0 and OpenID Connect (OIDC). It includes:

- A **Website** (Razor MVC Client)
- A **Backend-for-Frontend (BFF)** Web API
- A **Backend API** (business logic or service layer)
- A **Custom Identity Provider (IdP)** with support for authorization code and on-behalf-of flows

---

## 🔁 Authentication & Authorization Flow

### 🧍 1. User logs into the **Website**

- The website is a registered OAuth client (`mywebsite-clientid`)
- It uses OIDC to authenticate users and receive:
  - An `id_token` (for identifying the user)
  - An `access_token` (used to call APIs)

### 📡 2. Website calls the **BFF API**

- The website uses the `access_token` in the `Authorization: Bearer` header.
- The token’s `aud` (audience) must be set to the BFF API's client ID (`mybffapi-clientid`).
- The BFF validates the token against the configured audience.

### 🔄 3. BFF calls the **Backend API** using OBO

- The BFF needs to call the backend API on behalf of the user.
- It requests a new token from the Identity Provider using:
  - `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
  - `assertion=<user's original access_token>`
  - `requested_token_use=on_behalf_of`
  - `audience=mybackendapi-clientid`
- The IDP validates the incoming token and issues a new access token for the backend API.

### 🛠️ 4. Backend API processes the request

- The Backend API receives the new access token with:
  - `aud = mybackendapi-clientid`
  - `sub = original user id`
  - Optional roles or scopes based on user-client-role associations

---

## ✅ Client Registrations

You must register three clients:

| Client ID             | Description                     | Role            |
|-----------------------|----------------------------------|-----------------|
| `mywebsite-clientid`  | Razor website                   | Public OAuth client (OIDC login) |
| `mybffapi-clientid`   | Web API acting as BFF           | Confidential client & resource |
| `mybackendapi-clientid` | Downstream API                | Resource server only |

---

## 🔐 Audience (`aud`) Handling

| Token Used For        | Target Audience (`aud`)         |
|-----------------------|----------------------------------|
| Calling BFF from Website | `mybffapi-clientid`           |
| Calling Backend API from BFF (OBO) | `mybackendapi-clientid` |

Tokens must always have the correct `aud` for the service they are intended for.

---

## 🧠 Summary

- **OIDC** is used to authenticate the user and return an `id_token`
- **OAuth 2.0** is used to authorize access to APIs using `access_token`s
- The **audience** claim (`aud`) is critical for token validation
- The **On-Behalf-Of (OBO)** flow is used by the BFF to call the backend API with user context

---

## 🛠️ Enhancements

The custom Identity Provider supports:

- Authorization Code Flow with nonce, state, and scope
- User and Client registration endpoints
- Role-based access per user-client
- `/token` endpoint with support for audience targeting and OBO flow

## 🔄 Token Flow Strategy & OBO Justification

### 🧩 The Problem with Multiple BFFs and Static Audience Assignment

In traditional OAuth 2.0 Authorization Code Flow, when a user logs in via the website (Razor MVC), the access token that is issued is tied to:

- The `client_id` of the website
- Predefined `scope`s configured in the Identity Provider
- A **fixed audience** (usually the frontend itself or a single backend API)

> 🎯 This makes it **difficult to support multiple downstream APIs (BFFs)** with different audience values — because the `aud` is assigned during login and cannot be changed dynamically.

### ❌ Constraint

If you **do not use the On-Behalf-Of flow**, you are limited to **one audience per login session** — meaning:

> 🔐 The frontend (website) can only get a valid access token for **one BFF** during login.

If you have more than one BFF:
- You **cannot dynamically switch** between tokens for different BFFs
- You would need to request **all possible scopes at login**, which becomes unmanageable and brittle

---

### ✅ Solution: Use OBO for Flexibility

By using the **On-Behalf-Of (OBO)** flow, the frontend can:
- Reuse its original access token (issued at login)
- Dynamically request **a new access token** for any specific `audience` (BFF, backend API, etc.)
- Get a properly scoped token that is **trusted by the target API**

```http
POST /token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
client_id=mywebsite-clientid
requested_token_use=on_behalf_of
assertion=<original_access_token>
audience=mybffapi-clientid


# 🧩 Identity Provider: Audience-Specific Access Tokens via Scopes

This document explains how the Identity Provider (IdP) dynamically issues access tokens with the correct audience (`aud`) for downstream APIs based on scopes requested by OAuth clients.

## 🧱 Architecture: Key Components

### 1. `OAuthClient` Registration

Each application (Website, BFF, Backend APIs) is registered with a unique `clientId`.  
Clients include:
- A `redirectUri`
- A list of `allowedScopes` (optional, to restrict which scopes they can request)

Example:

```json
POST /clients
{
  "clientId": "mywebsite-clientid",
  "name": "Website",
  "redirectUri": "https://localhost:55265/signin-oidc",
  "allowedScopes": ["openid", "profile", "email", "bff.read"]
}
```

---

### 2. `ScopeDefinition` Registration

Scopes define named permissions (e.g., `bff.read`) and map them to a valid `audience` (the `clientId` of an API).  
These scopes are registered via:

```json
POST /scopes
{
  "name": "bff.read",
  "audience": "bffapi-clientid",
  "description": "Allows reading from the BFF API"
}
```

The IdP validates that the `audience` exists as a registered client before accepting the scope.

---

### 3. `UserClientRole` Registration

Users can be associated with roles per audience (application).  
This is used when issuing access tokens with `roles` claims.

```json
POST /user-roles
{
  "clientId": "bffapi-clientid",
  "subjectId": "user3",
  "role": "Admin"
}
```

This structure mimics Azure Entra ID’s "App Roles" per application.

---

## 🔐 How Access Tokens Are Generated with Correct Audience

When a client (e.g., the Website) initiates an authorization code flow and requests a scope such as:

```
scope=openid profile email bff.read
```

The token generation pipeline:

1. **Validates** that the requesting client is allowed to ask for `bff.read`
2. **Resolves** the scope `bff.read` to audience `mybffapi-clientid`
3. **Queries** the `UserClientRole` repository to find roles the user has in that API
4. **Generates** the access token with:
   - `"aud": "mybffapi-clientid"`
   - `"scope": "bff.read"`
   - `"roles": [...]` (based on the user-role mapping)
   - `"sub"`, `"iat"`, `"exp"`, etc.

This access token can now be safely presented to the BFF API and validated using the expected audience and role claims.

---

## 🔁 Summary of Components and Their Roles

| Component               | Purpose                                                             |
|------------------------|----------------------------------------------------------------------|
| `OAuthClient`          | Registers applications and their allowed scopes                     |
| `ScopeDefinition`      | Links named scopes to target APIs via audience                      |
| `UserClientRole`       | Assigns users to roles per audience                                 |
| `IScopeRepository`     | Lookup table to resolve scopes into audiences during token creation |
| `GenerateAccessToken`  | The method that assembles claims and calculates the audience        |

---

## ✅ Result

The website can now:
- Request access tokens with `scope=bff.read`
- Receive a token scoped to the BFF API (`aud=mybffapi-clientid`)
- Include role-based claims usable by the BFF
- Enable BFF to use the token or further exchange it for downstream access via OBO

This design brings the system closer to real-world identity providers like Azure Entra ID or Auth0.