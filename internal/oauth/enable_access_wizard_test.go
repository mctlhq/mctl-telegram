package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStepIndicatorInWizardMode verifies that the step indicator is rendered
// and shows the active step when WizardMode is true.
func TestStepIndicatorInWizardMode(t *testing.T) {
	rec := httptest.NewRecorder()
	renderEnablePhone(rec, enablePhonePage{
		Issuer:      "https://tg.test",
		EnableToken: "tok",
		WizardMode:  true,
		WizardStep:  3,
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Step") {
		t.Fatalf("step indicator absent in wizard mode; body=%s", body)
	}
	if !strings.Contains(body, "class=\"active\"") {
		t.Errorf("no active step marked in wizard mode; body=%s", body)
	}
}

// TestStepIndicatorAbsentNonWizard verifies that no step indicator is rendered
// outside wizard mode.
func TestStepIndicatorAbsentNonWizard(t *testing.T) {
	rec := httptest.NewRecorder()
	renderEnablePhone(rec, enablePhonePage{
		Issuer:      "https://tg.test",
		EnableToken: "tok",
		WizardMode:  false,
		WizardStep:  3,
	})
	body := rec.Body.String()
	if strings.Contains(body, "class=\"steps\"") {
		t.Errorf("step indicator must be absent when WizardMode=false; body=%s", body)
	}
}

// TestNotificationBannerWizardOnly verifies the device-notification banner
// appears in wizard mode and is absent otherwise.
func TestNotificationBannerWizardOnly(t *testing.T) {
	wizardRec := httptest.NewRecorder()
	renderEnablePhone(wizardRec, enablePhonePage{
		Issuer:     "https://tg.test",
		WizardMode: true,
	})
	if !strings.Contains(wizardRec.Body.String(), "notice") {
		t.Errorf("device notification banner absent in wizard mode")
	}

	plainRec := httptest.NewRecorder()
	renderEnablePhone(plainRec, enablePhonePage{
		Issuer:     "https://tg.test",
		WizardMode: false,
	})
	if strings.Contains(plainRec.Body.String(), "class=\"notice\"") {
		t.Errorf("device notification banner must be absent in non-wizard mode")
	}
}
