package rdpproxy

import "context"

// NativeResolver adapts mstsc front-side credentials to resolved Turjmp target authorization.
type NativeResolver struct {
	api apiClient
}

// NewNativeResolver creates a resolver for future native engine auth callbacks.
func NewNativeResolver(api apiClient) *NativeResolver {
	return &NativeResolver{api: api}
}

// Resolve validates route username/password through the backend and returns a target-only auth result.
func (r *NativeResolver) Resolve(ctx context.Context, routeUsername, password, remoteAddr string) (authResult, error) {
	auth, err := r.api.ResolveNativeRDP(ctx, routeUsername, password, remoteAddr)
	if err != nil {
		return authResult{}, err
	}
	if err := validateRDPAuth(auth); err != nil {
		return authResult{}, err
	}
	return auth, nil
}
