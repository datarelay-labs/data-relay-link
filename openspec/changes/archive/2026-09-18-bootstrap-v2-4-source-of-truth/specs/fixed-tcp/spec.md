# Spec Delta

## Purpose

Defines Fixed TCP as a Service Object subtype and its endpoint-allocation rules when used by a Remote Service.

## ADDED Requirements

### Requirement: Fixed TCP is a Service Object subtype
Fixed TCP SHALL be represented as a Service Object subtype defining the destination TCP service port and SHALL NOT form a separate policy model.

#### Scenario: Fixed TCP object is used
- **WHEN** an operator creates a Fixed TCP Service Object
- **THEN** the operator SHALL define the destination service port and SHALL NOT choose the external listen port

### Requirement: Fixed TCP endpoint allocation uses a separate pool
A Remote Service using a Fixed TCP Service Object SHALL receive its external endpoint from a Fixed TCP pool that does not overlap the normal Remote Service endpoint pool.

#### Scenario: Fixed TCP service is activated
- **WHEN** endpoint allocation is available for a Remote Service using Fixed TCP
- **THEN** the system SHALL allocate from the Fixed TCP pool without consuming an endpoint from the normal pool

### Requirement: Endpoint-pool class cannot change in place
An existing Remote Service SHALL NOT be edited in place between standard TCP and Fixed TCP endpoint-pool classes.

#### Scenario: Cross-pool edit is requested
- **WHEN** an existing Remote Service is changed from standard TCP to Fixed TCP or from Fixed TCP to standard TCP
- **THEN** the system SHALL reject the edit with no change applied and SHALL require delete-and-recreate semantics
