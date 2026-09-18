# remote-service Specification

## Purpose
Defines Agent-local Remote Service creation, validation, degradation, synchronization, and stable endpoint behavior for v2.4.

## Requirements

### Requirement: Remote Service is Agent-local connectivity
A Remote Service SHALL be configured in the Agent Host context and SHALL represent actual connectivity independently from Access Policy rules.

#### Scenario: Policy does not create connectivity
- **WHEN** an Access Policy Rule is created or deleted
- **THEN** the system SHALL NOT create or delete a Remote Service solely because of that Rule change

### Requirement: Remote Service references resolve to one target and one supported service
A Remote Service destination SHALL resolve to one target and SHALL use exactly one Service Object. TCP and Fixed TCP SHALL be supported; UDP SHALL be rejected for Remote Service use.

#### Scenario: Unsupported or ambiguous dependency
- **WHEN** a Remote Service references a multi-target destination, a Service Group, UDP Service Object, or unresolved required reference
- **THEN** creation or edit SHALL fail with no configuration change applied

### Requirement: Valid but unreachable configuration is retained
Reachability failure SHALL NOT invalidate an otherwise valid Remote Service configuration.

#### Scenario: Destination or Server is temporarily unreachable
- **WHEN** a valid Remote Service cannot currently reach its destination or the DRLink Server
- **THEN** its configuration SHALL be retained and its user-facing state SHALL be DEGRADED rather than rejected

### Requirement: Endpoint identity is stable across temporary failures
A previously allocated Remote Service endpoint SHALL be preserved across temporary runtime or Server connectivity failures.

#### Scenario: Existing endpoint during disconnect
- **WHEN** an existing Remote Service becomes DEGRADED because synchronization or runtime connectivity is unavailable
- **THEN** the system SHALL retain its endpoint reservation and SHALL restore service without reallocating the endpoint when connectivity returns
