{
  description = "rust-bitcoin-core - A Bitcoin Core implementation in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      {
        # Default package: static musl build
        packages.default = let
          rustPlatformMusl = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in rustPlatformMusl.buildRustPackage {
          pname = "rust-bitcoin-core";
          version = "0.1.0";
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
            pkgsStatic.stdenv.cc
          ];
          
          buildInputs = with pkgs.pkgsStatic; [
            openssl
            sqlite
          ];
          
          # Environment variables for static linking
          OPENSSL_STATIC = "1";
          OPENSSL_LIB_DIR = "${pkgs.pkgsStatic.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.pkgsStatic.openssl.dev}/include";
          PKG_CONFIG_PATH = "${pkgs.pkgsStatic.openssl.dev}/lib/pkgconfig";
          
          # Force cargo to use the musl target
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";
          CC_x86_64_unknown_linux_musl = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static -C link-arg=-static";
          
          # Override buildPhase to use the correct target
          buildPhase = ''
            runHook preBuild
            
            echo "Building rust-bitcoin-core with musl target..."
            cargo build \
              --release \
              --target x86_64-unknown-linux-musl \
              --package bitcoin-node \
              --offline \
              -j $NIX_BUILD_CORES
            
            cargo build \
              --release \
              --target x86_64-unknown-linux-musl \
              --package bitcoin-cli \
              --offline \
              -j $NIX_BUILD_CORES
            
            runHook postBuild
          '';
          
          installPhase = ''
            runHook preInstall
            
            mkdir -p $out/bin
            cp target/x86_64-unknown-linux-musl/release/bitcoin-node $out/bin/
            cp target/x86_64-unknown-linux-musl/release/bitcoin-cli $out/bin/
            
            runHook postInstall
          '';
          
          # Ensure static linking
          doCheck = false; # Tests don't work well with static linking
          
          # Verify the binary is statically linked
          postInstall = ''
            echo "Checking if binaries are statically linked..."
            file $out/bin/bitcoin-node
            file $out/bin/bitcoin-cli
            # Strip the binaries to reduce size
            ${pkgs.binutils}/bin/strip $out/bin/bitcoin-node
            ${pkgs.binutils}/bin/strip $out/bin/bitcoin-cli
          '';
          
          meta = with pkgs.lib; {
            description = "A Bitcoin Core implementation in Rust";
            homepage = "https://github.com/yourusername/rust-bitcoin-core";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
        
        # Alternative dynamic build (non-static)
        packages.bitcoin-core-dynamic = pkgs.rustPlatform.buildRustPackage {
          pname = "rust-bitcoin-core-dynamic";
          version = "0.1.0";
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];
          
          buildInputs = with pkgs; [
            openssl
            sqlite
          ];
          
          meta = with pkgs.lib; {
            description = "A Bitcoin Core implementation in Rust (dynamic build)";
            homepage = "https://github.com/yourusername/rust-bitcoin-core";
            license = licenses.mit;
            maintainers = [ ];
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            rustToolchain
            
            # Build tools
            pkg-config
            pkgsStatic.stdenv.cc
            clang
            llvmPackages.bintools
            
            # Static dependencies
            pkgsStatic.openssl
            pkgsStatic.sqlite
            
            # Dynamic dependencies for development
            openssl
            openssl.dev
            sqlite
            
            # Development tools
            cargo-edit
            cargo-outdated
            cargo-audit
            cargo-watch
            cargo-expand
            cargo-flamegraph
            rustfmt
            clippy
            
            # Debugging
            gdb
            lldb
            valgrind
            
            # Performance analysis
            perf-tools
            heaptrack
            
            # Documentation
            mdbook
            graphviz
            
            # Bitcoin tools for testing
            bitcoind
            electrs
            
            # Network debugging
            tcpdump
            wireshark-cli
            netcat
            
            # Git tools
            gh
            git-cliff
            
            # JSON/TOML tools
            jq
            yq
            taplo
          ];

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          
          # For musl static linking
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";
          CC_x86_64_unknown_linux_musl = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";
          
          # For OpenSSL static linking
          OPENSSL_STATIC = "1";
          OPENSSL_LIB_DIR = "${pkgs.pkgsStatic.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.pkgsStatic.openssl.dev}/include";
          PKG_CONFIG_PATH = "${pkgs.pkgsStatic.openssl.dev}/lib/pkgconfig";
          
          shellHook = ''
            echo "🦀 Welcome to rust-bitcoin-core development environment!"
            echo ""
            echo "Available commands:"
            echo "  cargo build           - Build the project (static musl)"
            echo "  cargo test            - Run tests"
            echo "  cargo bench           - Run benchmarks"
            echo "  cargo doc --open      - Generate and view documentation"
            echo "  cargo clippy          - Run linter"
            echo "  cargo fmt             - Format code"
            echo ""
            echo "Bitcoin tools:"
            echo "  bitcoind              - Bitcoin Core daemon"
            echo "  electrs               - Electrum server"
            echo ""
            echo "Build targets:"
            echo "  Default: x86_64-unknown-linux-musl (static)"
            echo ""
            
            # Add static libusb to the shell
            export RUSTFLAGS="-C target-feature=+crt-static"
            
            # Set up pre-commit hooks if .githooks exists
            if [ -d .git ] && [ -d .githooks ]; then
              current_hooks_path=$(git config core.hooksPath || echo "")
              if [ "$current_hooks_path" != ".githooks" ]; then
                echo "📎 Setting up Git hooks..."
                git config core.hooksPath .githooks
                echo "✅ Git hooks configured!"
              fi
            fi
            
            # Create .env file for local development if it doesn't exist
            if [ ! -f .env ]; then
              cat > .env << 'EOF'
# Local development configuration
RUST_LOG=debug
RUST_BACKTRACE=1
BITCOIN_NETWORK=regtest
RPC_PORT=8332
P2P_PORT=8333
DATABASE_PATH=./data
EOF
              echo "📝 Created .env file for local development"
            fi
          '';
        };
      }
    );
}