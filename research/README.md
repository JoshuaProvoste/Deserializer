# Security Research: Deserialization Audits

This directory serves as the project's research core, dedicated to the technical analysis and documentation of critical security flaws in high-impact software components. The focus is on the systematic exploration of deserialization vulnerabilities, mapping execution paths that allow seemingly harmless data inputs to be transformed into vectors for full system compromise.

The fundamental purpose is to consolidate a specialized knowledge repository detailing the inherent risks associated with the insecure management of objects and states. Through the study of attack surfaces and the validation of infrastructure-level impacts, this work seeks to strengthen technological resilience and promote greater transparency in the security of modern tools and frameworks.

## Research writeups that this scanner supported

**Deserializer** directly supports security research by locating insecure deserialization paths across various large-scale projects and environments. Concretely, it makes it easy to enumerate where applications deserialize model/artifact blobs and prioritize the high-risk code paths that execute during loading flows, accelerating root-cause analysis and PoC development for critical vulnerabilities.

### Trend AI - Zero Day Initiative (ZDI)

- **TensorFlow (v2.21.0)**:
  - **Impact**: Critical RCE on developer workstations and MLOps infrastructure.
  - **Details**: `saved_model_cli` uses `numpy.load(..., allow_pickle=True)` via `file_io.FileIO` when processing the `--inputs` flag. This allows loading malicious `.npy`/`.npz` files from remote URIs (SMB/UNC), leading to code execution during deserialization.
  - **RCE PoC**: [RCE in tensorflow v2.21.0](tensorflow_v2.21.0/README.md)
- **LangGraph (v1.1.6)**:
  - **Impact**: Critical RCE on agentic AI infrastructure and GPU/TPU clusters.
  - **Details**: `JsonPlusSerializer` defaults to a permissive policy (`allowed_msgpack_modules=True`) for `msgpack` extensions. An attacker can craft a `msgpack` payload using extension code 0 (`EXT_CONSTRUCTOR_SINGLE_ARG`) to trigger arbitrary module imports and code execution, bypassing CVE-2026-27794.
  - **RCE PoC**: [RCE in langgraph v1.1.6](langgraph%20_v1.1.6/README.md)
- **Django (v6.0.4)**:
  - **Impact**: Critical RCE via cache poisoning (Redis/Memcached) or SMB/UNC path redirection.
  - **Details**: `RedisCache` and `PyMemcacheCache` use `pickle.loads()` by default for data retrieval. Attackers with access to the cache layer can inject malicious serialized objects. Additionally, path-based configurations on Windows resolve UNC paths, enabling remote exploitation over SMB.
  - **RCE PoC**: [RCE in django v6.0.4](django_v6.0.4/README.md)
- **VibeVoice (v0.0.1)**:
  - **Impact**: Critical RCE on developer workstations and AI-as-a-Service (AIaaS) platforms.
  - **Details**: `VibeVoiceTokenizerProcessor` utilizes `torch.load()` and `numpy.load()` on untrusted audio file paths. On Windows, this allows for **Infrastructure Hijacking via UNC Path Redirection**, where an attacker provides a remote SMB path (e.g., `\\attacker-ip\share\exploit.pt`) to execute a malicious payload during deserialization.
  - **RCE PoC**: [RCE in vibevoice v0.0.1](vibevoice_v0.0.1/README.md)
- **Hugging Face Hub (v1.11.0)**:
  - **Impact**: Critical RCE on Data Science workstations and Automated ML Training Pipelines.
  - **Details**: `from_pretrained_fastai()` downloads and deserializes a `model.pkl` from remote repositories using FastAI's `load_learner` (pickle-based). Attackers can trigger code execution by hosting a malicious model or mocking the Hub API via `HF_ENDPOINT` to serve a malicious payload.
  - **RCE PoC**: [RCE in huggingface-hub v1.11.0](huggingface-hub_v1.11.0_Hub-to-RCE_via_from_pretrained_fastai/README.md)
- **Hugging Face Hub (v1.11.0)**:
  - **Impact**: Critical RCE on Windows-based AI/ML development pipelines and DevOps automation.
  - **Details**: `load_torch_model()` defaults to `weights_only=False`, allowing unrestricted `pickle.load` via `torch.load()`. On Windows, this is exploitable remotely via **UNC Path Redirection**, where loading a model from a network share (e.g., `\\attacker-ip\share\pytorch_model.bin`) executes an attacker-controlled payload.
  - **RCE PoC**: [RCE in huggingface-hub v1.11.0 (Supply Chain)](huggingface-hub_v1.11.0_Supply_Chain_RCE_via_load_torch_model_Defaults/README.md)
- **LeRobot (v0.5.1) - PolicyServer**:
  - **Impact**: Critical RCE on robotics research infrastructure and inference servers.
  - **Details**: `PolicyServer` is an unauthenticated gRPC service that uses `pickle.loads` on incoming `request.data` in `SendPolicyInstructions` and `SendObservations`. Any network-adjacent attacker can execute arbitrary code by sending a malicious serialized object without authentication.
  - **RCE PoC**: [RCE in lerobot v0.5.1 (PolicyServer)](lerobot_v0.5.1_Unauthenticated_RCE_in_PolicyServer/README.md)
- **LeRobot (v0.5.1) - LearnerService**:
  - **Impact**: Critical RCE on GPU-based training clusters and distributed RL infrastructure.
  - **Details**: `LearnerService` exposes an unauthenticated gRPC stream `SendInteractions` which accepts byte streams. These streams are passed to `bytes_to_python_object` containing an insecure `pickle.load` sink. An attacker spoofing an Actor instance can achieve code execution on the central training server.
  - **RCE PoC**: [RCE in lerobot v0.5.1 (LearnerService)](lerobot_v0.5.1_Unauthenticated_RCE_in_LearnerService/README.md)
- **MuJoCo (v3.7.0) - TimeSeries**:
  - **Impact**: Critical RCE on robotics research workstations and automated simulation pipelines.
  - **Details**: `mujoco.sysid.TimeSeries.load_from_disk` utilizes `numpy.load(..., allow_pickle=True)` to process archived signal data. On Windows, providing a Universal Naming Convention (UNC) path redirects the application to fetch and deserialize a malicious payload from an attacker-controlled SMB share.
  - **RCE PoC**: [RCE in MuJoCo v3.7.0 (UNC Redirection)](mujoco_v3.7.0_RCE_via_UNC_Path_Redirection/README.md)
- **MuJoCo (v3.7.0) - SystemTrajectory**:
  - **Impact**: Critical RCE on collaborative robotics platforms and benchmarking workstations.
  - **Details**: `mujoco.sysid.SystemTrajectory.load_from_disk` uses `numpy.load(..., allow_pickle=True)` to load trajectory archives (`.npz`). This enables a supply chain attack where researchers unknowingly execute code by loading poisoned benchmark datasets distributed in the robotics community.
  - **RCE PoC**: [RCE in MuJoCo v3.7.0 (Supply Chain)](mujoco_v3.7.0_Supply_Chain_Compromise_via_SystemTrajectory/README.md)


### Google - Open Source Software Vulnerability Reward Program (OSS VRP)

- **Brax (v0.14.2)**:
  - **Impact**: Critical RCE on compute nodes and TPU/GPU pods.
  - **Details**: `load_params` in `brax.io.model` uses `etils.epath` to download and deserialize malicious parameters via `pickle.loads` from remote URIs (SMB, GCS, S3).
  - **Pull Request**: https://github.com/google/brax/pull/667
  - **RCE PoC**: [RCE in brax v0.14.2](brax_v0.14.2/README.md)
- **Dopamine (v2.0)**:
  - **Impact**: Critical RCE in distributed research clusters.
  - **Details**: `load_statistics` and `Checkpointer` use `tf.io.gfile` to deserialize pickles from attacker-controlled remote paths or malicious `gin-config` injections.
  - **Issue**: https://github.com/google/dopamine/issues/236
  - **RCE PoC**: [RCE in dopamine v2.0](dopamine_v2.0/README.md)
- **PyGlove (v0.4.5)**:
  - **Impact**: Critical RCE via JSON APIs and distributed tuning.
  - **Details**: `_OpaqueObject` allows automatic pickle decoding embedded in JSON. Also vulnerable in `sandbox_call` and `fsspec` URI loading flows.
  - **Pull Request**: https://github.com/google/pyglove/pull/404
  - **RCE PoC**: [RCE in pyglove v0.4.5](pyglove_v0.4.5/README.md)
- **Learned Optimization (v0.0.1)**:
  - **Impact**: Critical RCE in HPC research environments and TPU/GPU pods.
  - **Details**: `read_npz` in `learned_optimization.baselines.utils` uses `numpy.load(..., allow_pickle=True)` on researcher-controlled paths (GCS, SMB), enabling the execution of arbitrary Python objects during deserialization.
  - **Pull Request**: https://github.com/google/learned_optimization/pull/342
  - **RCE PoC**: [RCE in learned_optimization v0.0.1](learned_optimization_v0.0.1/README.md)
- **Vertex AI (v1.147.0)**:
  - **Impact**: Critical RCE on developer workstations, CI/CD runners (MLOps), and research environments.
  - **Details**: Several sinks in Predictors and Agent/Reasoning engines allow loading malicious artifacts via `pickle`/`cloudpickle` from remote URIs (GCS, SMB/UNC). Vulnerabilities can be chained via `AIP_STORAGE_URI` or `staging_bucket` injection for remote exploitation.
  - **Pull Request**: https://github.com/googleapis/python-aiplatform/pull/6589
  - **RCE PoC**: [RCE in google-cloud-aiplatform v1.147.0](google_cloud_aiplatform_v1.147.0/README.md)
- **Agent Development Kit (ADK) (v1.30.0)**:
  - **Impact**: Critical RCE on developer workstations and AI infrastructure during session management.
  - **Details**: Insecure deserialization in the migration loop (`_row_to_event`) and shared state schemas (`DynamicPickleType`) allows for zero-interaction exploitation via remote database URIs (SMB/UNC) or shared database poisoning (MySQL/Spanner).
  - **Pull Request**: https://github.com/google/adk-python/pull/5333
  - **RCE PoC**: [RCE in google-adk v1.30.0](google_adk_v1.30.0/README.md)