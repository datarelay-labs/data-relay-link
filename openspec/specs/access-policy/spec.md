# access-policy Specification

## Purpose
Defines the shared v2.4 Access Policy mode semantics while preserving separation between authorization and actual connectivity.

## Requirements

### Requirement: Policy mode determines matching semantics
Each Remote Access, Internet Access, and AI Access policy SHALL use either BLACKLIST or WHITELIST mode.

#### Scenario: BLACKLIST evaluation
- **WHEN** BLACKLIST mode is active
- **THEN** any enabled matching Rule SHALL deny the request and no enabled matching Rule SHALL result in allow

#### Scenario: WHITELIST evaluation
- **WHEN** WHITELIST mode is active
- **THEN** any enabled matching Rule SHALL allow the request and no enabled matching Rule SHALL result in deny

### Requirement: Unconfigured policy allows access
Before an Access Policy is configured, the effective policy result SHALL be ALLOW.

#### Scenario: No policy and no rules exist
- **WHEN** a policy plane has no configured Policy Mode
- **THEN** the CLI SHALL communicate that no access restrictions are configured and effective access SHALL be ALLOW

### Requirement: First non-interactive Rule establishes policy mode explicitly
If no Policy Mode exists, the first non-interactive Rule creation SHALL include the requested mode.

#### Scenario: First AI one-shot omits mode
- **WHEN** an AI one-shot command creates the first Rule without a mode
- **THEN** the command SHALL fail with no changes applied

### Requirement: Policy authorization does not create connectivity
Policy evaluation SHALL authorize or deny use of existing connectivity and SHALL NOT itself create Remote Services or endpoints.

#### Scenario: Rule matches but no usable connectivity exists
- **WHEN** a request is allowed by policy but the required Remote Service or target is unavailable
- **THEN** effective connectivity SHALL remain unavailable
