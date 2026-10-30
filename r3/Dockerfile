ARG RUST_IMAGE=rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff
FROM ${RUST_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /artifact
COPY . /artifact

RUN python3 -m venv /opt/e3-figure-venv \
    && /opt/e3-figure-venv/bin/python -m pip install --no-cache-dir \
       --requirement /artifact/requirements-e3-figure.txt

# Populate the registry cache according to every complete lockfile, then keep
# all reproduction commands offline. Path dependencies are already bundled.
RUN cargo fetch --locked --manifest-path sources/e1_original/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r1_randomized_dummy/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r2_presentation/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r3_blind_update/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r4_checked_crs/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r4_service/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/r6_tree_maintenance/adapter/Cargo.toml \
    && cargo fetch --locked --manifest-path sources/synthesis_patch/ark-r1cs-std/Cargo.toml

ENV CARGO_NET_OFFLINE=true \
    RAYON_NUM_THREADS=10 \
    OMP_NUM_THREADS=1 \
    E3_FIGURE_VENV=/opt/e3-figure-venv \
    PATH=/opt/e3-figure-venv/bin:$PATH

RUN python3 scripts/recompute_existing.py

ENTRYPOINT ["/artifact/docker/entrypoint.sh"]
CMD ["recompute"]
