# Service-name and port registry

`service-names-port-numbers.csv` is the unmodified IANA registry, downloaded on 2026-11-11 from [IANA's CSV](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv). IANA and IETF dedicate applicable rights in protocol registries under [CC0 1.0](https://www.iana.org/help/licensing-terms).

Run `scripts/update-port-registry.sh` and rebuild to update the embedded copy. Assignments are shown as registry information and do not establish which service actually runs on a device.
