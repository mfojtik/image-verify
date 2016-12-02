package main

import (
	"log"

	"github.com/containers/image/signature"
	"github.com/containers/image/transports"
	"github.com/containers/image/types"
)

// To sign and push the image for testing:
//
// 1) oc project test
// 2) oc create imagestream origin-pod
// 3) oadm policy add-cluster-role-to-user system:image-signer test-admin --as=system:admin
// 4) docker login -u test-admin -p $(oc whoami -t) -e test@dev 172.30.74.246:5000
// 5) skopeo --tls-verify=false copy --sign-by mfojtik@redhat.com docker://docker.io/openshift/origin-pod atomic:172.30.74.246:5000/test/origin-pod:latest
// 6) docker logout 172.30.74.246:5000
// 7) gpg --armor --export mfojtik@redhat.com > mfojtik-public.gpg
//

const (
	// change the OpenShift Registry address here
	imageToVerify = "atomic:172.30.167.99:5000/test/origin-pod:latest"
)

func main() {
	ctx := &types.SystemContext{
		DockerInsecureSkipTLSVerify: true,
		DockerAuthConfig: &types.DockerAuthConfig{
			// the user name
			Username: "test-admin",
			// oc whoami -t
			Password: "7jSZ7xk8TkG5Hk06GIbEEyddOqogP5VUrWcerPLyL7g",
		},
	}
	ref, err := transports.ParseImageName(imageToVerify)
	if err != nil {
		panic(err)
	}
	img, err := ref.NewImage(ctx)
	if err != nil {
		panic(err)
	}
	defer img.Close()
	// get the policy from a secret?
	// This policy will reject all images except those in the "test" repository signed by
	// the public GPG key.
	policy, err := signature.NewPolicyFromBytes([]byte(`
{
  "default": [{"type": "reject"}],
	"transports": {
		"atomic": {
			"172.30.167.99:5000/test": [
				{
					"type": "signedBy",
					"keyType": "GPGKeys",
					"keyPath": "/data/src/github.com/mfojtik/image-verify/mfojtik-public.gpg"
				}
			]
		}
	}
}
`))
	if err != nil {
		log.Fatalf("error reading policy: %v", err)
	}

	pc, err := signature.NewPolicyContext(policy)
	if err != nil {
		log.Fatalf("error making context: %v", err)
	}
	defer pc.Destroy()
	allowed, err := pc.IsRunningImageAllowed(img)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if allowed {
		log.Printf("image %q is ALLOWED to run", img.Reference().DockerReference())
	} else {
		log.Printf("image %q is DENIED to run", img.Reference().DockerReference())
	}
}
