# Artifact of *A forensic analysis of the Google Home: repairing compressed data without error correction*

```
By Hadrien Barral and Georges-Axel Jaloyan
```

## Overview

This tool is used in our *A forensic analysis of the Google Home: repairing compressed data without error correction*, to repair bitflip
in gzip compressed data.

The paper can be found [at Elsevier](https://www.sciencedirect.com/science/article/abs/pii/S2666281722001184) or on [Arxiv](https://arxiv.org/abs/2210.00856).

It consists on the following modules:
- `repairchunk`: the core module. See the tool help and thte paper for more details.
- `sasquatch`: a patched version of the sasquatch tool, with hooks to dump (respectively load) bad (respectively patched) gzip chunks
- `utils`: miscallenous utilities

## License

This tool is mostly released under Apache license. See `LICENSE` file.
Some parts have a specific licence (`sasquatch` and `ThreadPool.h`)
