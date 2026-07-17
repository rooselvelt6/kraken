# typed: false
# frozen_string_literal: true

# Homebrew formula for Kraken
#
# Usage:
#   brew install --formula ./scripts/homebrew/kraken.rb
#
# Or tap the repo:
#   brew tap rooselvelt6/kraken https://github.com/rooselvelt6/kraken.git
#   brew install kraken

class Kraken < Formula
  desc "Autonomous AI agent for cybersecurity operations"
  homepage "https://github.com/rooselvelt6/kraken"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/rooselvelt6/kraken/releases/download/v#{version}/kraken-macos-aarch64"
      sha256 "PLACEHOLDER_AARCH64_MACOS"
    else
      url "https://github.com/rooselvelt6/kraken/releases/download/v#{version}/kraken-macos-x86_64"
      sha256 "PLACEHOLDER_X86_64_MACOS"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/rooselvelt6/kraken/releases/download/v#{version}/kraken-linux-aarch64"
      sha256 "PLACEHOLDER_AARCH64_LINUX"
    elsif Hardware::CPU.s390x?
      url "https://github.com/rooselvelt6/kraken/releases/download/v#{version}/kraken-linux-x86_64"
      sha256 "PLACEHOLDER_X86_64_LINUX"
    else
      url "https://github.com/rooselvelt6/kraken/releases/download/v#{version}/kraken-linux-x86_64"
      sha256 "PLACEHOLDER_X86_64_LINUX"
    end
  end

  def install
    bin.install Dir["kraken*"].first => "kraken"
  end

  test do
    assert_match "kraken", shell_output("#{bin}/kraken --version", 2)
  end
end
