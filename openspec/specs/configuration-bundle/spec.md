# configuration-bundle Specification

## Purpose
Defines ConfigurationBundle as an idempotent declarative change set that reuses canonical DRLink validation and context-local apply semantics.

## Requirements

### Requirement: ConfigurationBundle is not a second source of truth
A ConfigurationBundle SHALL be input to canonical DRLink configuration processing and SHALL NOT become an independent authoritative database or policy engine.

#### Scenario: Bundle is applied
- **WHEN** a valid Bundle is submitted
- **THEN** its mutations SHALL converge on the same validation, impact analysis, authoritative state, audit, and runtime activation semantics used by canonical configuration operations

### Requirement: Bundle atomicity is context-local
A Server ConfigurationBundle SHALL be atomic only within Server-authoritative configuration, and an Agent ConfigurationBundle SHALL be atomic only within that Agent Host.

#### Scenario: Intent spans Server and Agent
- **WHEN** one user intent requires both Agent Remote Service configuration and Server Access Policy configuration
- **THEN** the system or AI SHALL split the work into independently validated operations or Bundles for each context

### Requirement: Bundle reapply is idempotent and deletion is explicit
Reapplying an equivalent ConfigurationBundle SHALL produce no effective change, omission SHALL NOT delete existing resources, and deletion SHALL require explicit absent semantics.

#### Scenario: Same Bundle is reapplied
- **WHEN** effective state already matches the submitted Bundle
- **THEN** the result SHALL be NO CHANGE and SHALL NOT create a new effective mutation solely because of reapplication

### Requirement: Secrets are excluded from Bundle state
ConfigurationBundle input and export SHALL NOT contain bootstrap tickets, private keys, bearer secrets, passwords, or equivalent credential material.

#### Scenario: Bundle contains prohibited secret material
- **WHEN** prohibited credential material is detected in a Bundle
- **THEN** validation SHALL fail closed and no configuration change SHALL be applied
