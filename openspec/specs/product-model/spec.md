# product-model Specification

## Purpose
Defines the canonical Data Relay Link v2.4 public concepts and the configuration boundaries operators and AI agents must use.

## Requirements

### Requirement: Canonical public model
Data Relay Link SHALL expose the v2.4 public model using Managed Host / DRLink Agent, Network Object/Group, Service Object/Group, Permission Object/Group, AI Identity, Remote Service, Remote Access, Internet Access, AI Access, BLACKLIST/WHITELIST, and ConfigurationBundle.

#### Scenario: Current terminology is presented
- **WHEN** an operator or AI agent discovers current v2.4 configuration concepts
- **THEN** the system SHALL use the canonical v2.4 public terms and SHALL NOT present the superseded intermediate model as current behavior

### Requirement: Server and Agent Host contexts remain distinct
The Server and Agent Host SHALL be separate configuration contexts with distinct authoritative responsibilities.

#### Scenario: Context-specific operation
- **WHEN** a configuration operation is executed
- **THEN** it SHALL mutate only resources owned by the current Server or Agent Host context unless an explicit cross-context synchronization contract exists

### Requirement: Superseded public model is not authoritative
Managed Endpoint, Published Service, Service Preset, ordered first-match ALLOW/DENY Rules, and AI Principal SHALL NOT redefine the current public model when they appear in legacy documents or internal implementation names.

#### Scenario: Legacy terminology is encountered
- **WHEN** an implementation detail or older document uses superseded terminology
- **THEN** the current v2.4 public contract SHALL remain defined by the canonical model
