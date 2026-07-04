"""Deployment connectors (Phase 1, Task 9+): push a renewed certificate from
a `ManagedCertificate` to wherever it's actually consumed.

`app.worker`'s `deploy` queue step is the only caller that matters --
`get_connector(target)` (see `base.py`) dispatches on `DeploymentTarget.kind`
to a connector implementing `DeployConnector.deploy(bundle) -> DeployResult`.
Only `pem` (filesystem) is implemented in this package so far; `pfx`/`jks`/
`iis` are added in Tasks 10/11.
"""
