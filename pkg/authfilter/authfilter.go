package authfilter

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

const (
	cacheTTL = 10 * time.Second
)

// NewAuthHandler wraps an http.Handler with Kubernetes authentication (TokenReview)
// and authorization (SubjectAccessReview), replicating the behavior of kube-rbac-proxy
// and controller-runtime's WithAuthenticationAndAuthorization.
func NewAuthHandler(handler http.Handler) (http.Handler, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("getting in-cluster config: %w", err)
	}

	authnClient, err := authenticationv1.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating authentication client: %w", err)
	}

	authzClient, err := authorizationv1.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating authorization client: %w", err)
	}

	authenticator, _, err := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               &apiserver.AnonymousAuthConfig{Enabled: false},
		TokenAccessReviewClient: authnClient,
		CacheTTL:                cacheTTL,
	}.New()
	if err != nil {
		return nil, fmt.Errorf("creating authenticator: %w", err)
	}

	authorizerObj, err := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: authzClient,
		AllowCacheTTL:             cacheTTL,
		DenyCacheTTL:              cacheTTL,
	}.New()
	if err != nil {
		return nil, fmt.Errorf("creating authorizer: %w", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, ok, err := authenticator.AuthenticateRequest(r)
		if err != nil || !ok {
			log.Printf("authentication failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		attributes := authorizer.AttributesRecord{
			User:            resp.User,
			Verb:            strings.ToLower(r.Method),
			Path:            r.URL.Path,
			ResourceRequest: false,
		}

		decision, _, err := authorizerObj.Authorize(r.Context(), attributes)
		if err != nil || decision != authorizer.DecisionAllow {
			log.Printf("authorization denied for user %s on %s %s: %v",
				resp.User.GetName(), r.Method, r.URL.Path, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		handler.ServeHTTP(w, r)
	}), nil
}
