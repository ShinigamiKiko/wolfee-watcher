module github.com/wolfee-watcher/cert-server

go 1.22

require (
	k8s.io/api v0.29.3
	k8s.io/apimachinery v0.29.3
	k8s.io/client-go v0.29.3
)

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/emicklei/go-restful/v3 v3.11.0
	github.com/go-logr/logr v1.3.0
	github.com/go-openapi/jsonpointer v0.19.6
	github.com/go-openapi/jsonreference v0.20.2
	github.com/go-openapi/swag v0.22.3
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.4
	github.com/google/gnostic-models v0.6.8
	github.com/google/gofuzz v1.2.0
	github.com/google/uuid v1.3.0
	github.com/josharian/intern v1.0.0
	github.com/json-iterator/go v1.1.12
	github.com/mailru/easyjson v0.7.7
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v1.0.2
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
	github.com/wolfee-watcher/pkg/mtls v0.0.0
	golang.org/x/net v0.19.0
	golang.org/x/oauth2 v0.10.0
	golang.org/x/sys v0.15.0
	golang.org/x/term v0.15.0
	golang.org/x/text v0.14.0
	golang.org/x/time v0.3.0
	google.golang.org/appengine v1.6.7
	google.golang.org/protobuf v1.33.0
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/klog/v2 v2.110.1
	k8s.io/kube-openapi v0.0.0-20231010175941-2dd684a91f00
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1
	sigs.k8s.io/yaml v1.3.0
)

replace github.com/wolfee-watcher/pkg/mtls => ../pkg/mtls

require github.com/wolfee-watcher/pkg/env v0.0.0

replace github.com/wolfee-watcher/pkg/env => ../pkg/env

require github.com/wolfee-watcher/pkg/logging v0.0.0

replace github.com/wolfee-watcher/pkg/logging => ../pkg/logging
