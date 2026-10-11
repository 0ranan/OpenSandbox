// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idlepolicy

import (
	"context"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"knative.dev/pkg/injection"
)

// SandboxGVR is the fast-sandbox Sandbox CR the annotation lives on.
var SandboxGVR = schema.GroupVersionResource{Group: "sandbox.fast.io", Version: "v1alpha2", Resource: "sandboxes"}

// DefaultCacheTTL bounds one CR read.
const DefaultCacheTTL = 30 * time.Second

// PolicySource answers the wake gate for one sandbox; must fail safe.
type PolicySource interface {
	WakeAllowed(ctx context.Context, namespace, sandboxID string) bool
}

// CRPolicySource reads the idle-policy annotation via a Kubernetes API GET
// of the Sandbox CR, with a TTL cache.
type CRPolicySource struct {
	client dynamic.Interface
	gvr    schema.GroupVersionResource
	ttl    time.Duration
	now    func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

type cacheKey struct {
	namespace string
	sandboxID string
}

type cacheEntry struct {
	allowed bool
	at      time.Time
}

func NewCRPolicySource(ctx context.Context, client dynamic.Interface, ttl time.Duration) *CRPolicySource {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	s := &CRPolicySource{
		client: client,
		gvr:    SandboxGVR,
		ttl:    ttl,
		now:    time.Now,
		cache:  make(map[cacheKey]cacheEntry),
	}
	go s.runCacheJanitor(ctx)
	return s
}

// NewInClusterCRPolicySource builds a CRPolicySource from the
// environment's Kubernetes credentials.
func NewInClusterCRPolicySource(ctx context.Context) (*CRPolicySource, error) {
	cfg := injection.ParseAndGetRESTConfigOrDie()
	cfg.UserAgent = "opensandbox-ingress-idlepolicy"
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewCRPolicySource(ctx, client, DefaultCacheTTL), nil
}

// WakeAllowed reports whether the sandbox's policy permits wake-on-access;
// every failure resolves to false.
func (s *CRPolicySource) WakeAllowed(ctx context.Context, namespace, sandboxID string) bool {
	key := cacheKey{namespace: namespace, sandboxID: sandboxID}
	s.mu.Lock()
	entry, ok := s.cache[key]
	s.mu.Unlock()
	if ok && s.now().Sub(entry.at) < s.ttl {
		return entry.allowed
	}

	allowed := s.fetch(ctx, namespace, sandboxID)

	s.mu.Lock()
	s.cache[key] = cacheEntry{allowed: allowed, at: s.now()}
	s.mu.Unlock()
	return allowed
}

func (s *CRPolicySource) fetch(ctx context.Context, namespace, sandboxID string) bool {
	// resourceVersion "0" = accepted-stale; the gate tolerates staleness by
	// design, and any error resolves to "no policy".
	cr, err := s.client.Resource(s.gvr).Namespace(namespace).Get(ctx, sandboxID, metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return false
	}
	return WakeAllowedOf(cr.GetAnnotations()[AnnotationKey])
}

func (s *CRPolicySource) runCacheJanitor(ctx context.Context) {
	ticker := time.NewTicker(s.ttl * 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := s.now().Add(-s.ttl)
			s.mu.Lock()
			for key, entry := range s.cache {
				if entry.at.Before(cutoff) {
					delete(s.cache, key)
				}
			}
			s.mu.Unlock()
		}
	}
}
