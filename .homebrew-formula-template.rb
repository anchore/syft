class Syft < Formula
  desc "A tool that generates a Software Bill Of Materials (SBOM) from container images and filesystems"
  homepage "https://github.com/anchore/syft"
  version "$VERSION"
  bottle :unneeded

  if OS.mac?
    if Hardware::CPU.intel?
      url "$DARWIN_AMD64_ASSET_URL"
      sha256 "$DARWIN_AMD64_ASSET_SHA256"
    end
  elsif OS.linux?
    if Hardware::CPU.intel?
      url "$LINUX_AMD64_ASSET_URL"
      sha256 "$LINUX_AMD64_ASSET_SHA256"
    end
  end

  def install
    bin.install "syft"
  end
end
