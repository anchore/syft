package static_binary

//"os"
//"path"
//"strings"

//"github.com/mitchellh/go-homedir"

//"github.com/anchore/syft/internal/log"

const (
// defaultProxies  = "https://proxy.golang.org,direct"
// directProxyOnly = "direct"
)

var (
// directProxiesOnly = []string{directProxyOnly}
)

type StaticBinaryCatalogerOpts struct {
	localSharedLibDir string
}

func NewStaticBinaryCatalogerOpts() StaticBinaryCatalogerOpts {
	g := StaticBinaryCatalogerOpts{}
	g.localSharedLibDir = "/opt/dev/int/domains/mf/mom-cpp/install/lib/"
	return g
}
