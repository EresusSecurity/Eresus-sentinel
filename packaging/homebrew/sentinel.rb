# Homebrew formula for Eresus Sentinel
# To publish: push this file to a tap repo (homebrew-tap)
# then users run: brew tap eresus-security/tap && brew install sentinel
#
# Update sha256 and url after each release.
# Generate sha256: shasum -a 256 sentinel-<version>-macos-universal2.dmg

class Sentinel < Formula
  desc "Deterministic AI security toolkit — model scanning, prompt firewalls, MCP security"
  homepage "https://eresussec.com"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/EresusSecurity/Eresus-sentinel/releases/download/v#{version}/sentinel-#{version}.arm64_monterey.bottle.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/EresusSecurity/Eresus-sentinel/releases/download/v#{version}/sentinel-#{version}.x86_64_monterey.bottle.tar.gz"
      sha256 "PLACEHOLDER_X86_SHA256"
    end
  end

  on_linux do
    url "https://github.com/EresusSecurity/Eresus-sentinel/releases/download/v#{version}/sentinel-#{version}-linux-x86_64.tar.gz"
    sha256 "PLACEHOLDER_LINUX_SHA256"
  end

  license "LicenseRef-ESL-1.1"

  bottle do
    root_url "https://github.com/EresusSecurity/Eresus-sentinel/releases/download/v#{version}"
  end

  def install
    bin.install "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel --version")
    assert_match "Usage:", shell_output("#{bin}/sentinel --help")
  end
end
