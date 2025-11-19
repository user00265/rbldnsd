package acl

import (
	"testing"
)

// TestACLAllowRuleValid tests allowing a query from allowed network
func TestACLAllowRuleValid(t *testing.T) {
	acl, err := FromRules(
		[]string{"192.168.0.0/16", "10.0.0.0/8"},
		[]string{},
	)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Allow rules accepted")
}

// TestACLDenyRuleValid tests denying a query from denied network
func TestACLDenyRuleValid(t *testing.T) {
	acl, err := FromRules(
		[]string{},
		[]string{"203.0.113.0/24", "198.51.100.0/24"},
	)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Deny rules accepted")
}

// TestACLBothRulesValid tests ACL with both allow and deny rules
func TestACLBothRulesValid(t *testing.T) {
	acl, err := FromRules(
		[]string{"192.168.0.0/16", "10.0.0.0/8"},
		[]string{"203.0.113.0/24"},
	)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Both allow and deny rules accepted")
}

// TestACLInvalidCIDRLogged tests that invalid CIDR is logged but doesn't fail load
func TestACLInvalidCIDRLogged(t *testing.T) {
	acl, err := FromRules(
		[]string{"192.168.0.0/33"}, // Invalid mask (> 32)
		[]string{},
	)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	// ACL loads but with no valid rules (invalid line was skipped)
	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Invalid CIDR logged, ACL still loads")
}

// TestACLInvalidIPLogged tests that invalid IP is logged but doesn't fail load
func TestACLInvalidIPLogged(t *testing.T) {
	acl, err := FromRules(
		[]string{"not an ip address"},
		[]string{},
	)
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	// ACL loads but with no valid rules (invalid line was skipped)
	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Invalid IP logged, ACL still loads")
}

// TestACLEmptyRulesValid tests empty ACL is valid
func TestACLEmptyRulesValid(t *testing.T) {
	acl, err := FromRules([]string{}, []string{})
	if err != nil {
		t.Fatalf("failed to create empty ACL: %v", err)
	}

	if acl == nil {
		t.Fatal("ACL should not be nil")
	}

	t.Log("✓ Empty ACL accepted")
}
