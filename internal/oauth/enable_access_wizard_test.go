package oauth

import (
	"net/http/httptest"
	"net/url"
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
		WizardStep:  wizardPhoneStep,
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

// TestWizardHasThreeSteps pins the self-connect wizard at three steps (sign
// in, phone number, done) on every screen that shows the indicator: the
// Permissions screen is gone and the send choice lives on the phone/QR
// screen (#1157). A leftover "of 4" or "Permissions" on any of them fails.
func TestWizardHasThreeSteps(t *testing.T) {
	screens := map[string]func(w *httptest.ResponseRecorder){
		"phone": func(w *httptest.ResponseRecorder) {
			renderEnablePhone(w, enablePhonePage{Issuer: "https://tg.test", EnableToken: "tok", WizardMode: true, WizardStep: wizardPhoneStep})
		},
		"code": func(w *httptest.ResponseRecorder) {
			renderEnableCode(w, enableCodePage{Issuer: "https://tg.test", EnableToken: "tok", Phone: "+1", WizardMode: true, WizardStep: wizardPhoneStep})
		},
		"password": func(w *httptest.ResponseRecorder) {
			renderEnablePassword(w, enablePasswordPage{Issuer: "https://tg.test", EnableToken: "tok", WizardMode: true, WizardStep: wizardPhoneStep})
		},
		"qr": func(w *httptest.ResponseRecorder) {
			renderEnableQR(w, enableQRPage{EnableToken: "tok", WizardMode: true})
		},
		"qr connecting": func(w *httptest.ResponseRecorder) {
			renderEnableQRConnecting(w, true)
		},
	}
	for name, render := range screens {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			render(rec)
			body := rec.Body.String()
			if strings.Contains(body, "<li>Permissions</li>") || strings.Contains(body, "of 4 ") {
				t.Errorf("%s screen still shows the four-step wizard; body=%s", name, body)
			}
			if strings.Contains(body, "<h1>Step") && !strings.Contains(body, "of 3 ") {
				t.Errorf("%s screen heading does not say \"of 3\"; body=%s", name, body)
			}
			if !strings.Contains(body, "<li>Done</li>") && !strings.Contains(body, "Done</li>") {
				t.Errorf("%s screen lost the Done step; body=%s", name, body)
			}
		})
	}
	// The wizard's phone screen also says why there are two confirmations.
	rec := httptest.NewRecorder()
	renderEnablePhone(rec, enablePhonePage{Issuer: "https://tg.test", EnableToken: "tok", WizardMode: true, WizardStep: wizardPhoneStep})
	if !strings.Contains(rec.Body.String(), "proved who you are") {
		t.Errorf("wizard phone screen does not explain the first sign-in")
	}
}

// TestEnableStart_WizardReadsSendChoiceFromForm pins that the send choice in
// wizard mode now comes from the checkbox on the phone screen, like the
// external-client path, since the Permissions screen that used to set it is
// gone. Before #1157 the wizard ignored the form field.
func TestEnableStart_WizardReadsSendChoiceFromForm(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	for _, tc := range []struct {
		name string
		form url.Values
		want bool
	}{
		{"checked", url.Values{"send_optin": {"on"}}, true},
		{"unchecked", url.Values{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := &enableSession{
				oc:        oauthCtx{ClientID: ConnectClientID, RedirectURI: testIssuer + "/telegram/connect/done"},
				uid:       1,
				tgID:      500100101,
				createdAt: srv.clock(),
				step:      stepPhone,
			}
			tok := "wiz-" + tc.name
			srv.mu.Lock()
			srv.enables[tok] = es
			srv.mu.Unlock()
			form := url.Values{"es": {tok}, "phone": {"+14155551234"}}
			for k, v := range tc.form {
				form[k] = v
			}
			rec := postForm(t, mux, "/oauth/telegram/enable_access/start", form)
			if rec.Code != 200 {
				t.Fatalf("start: status %d body=%s", rec.Code, rec.Body.String())
			}
			es.lock.Lock()
			got := es.sendOptIn
			es.lock.Unlock()
			if got != tc.want {
				t.Errorf("sendOptIn = %v, want %v: the wizard must read the checkbox on the phone screen", got, tc.want)
			}
		})
	}
}
