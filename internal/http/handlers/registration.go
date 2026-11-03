package handlers

import (
	"context"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

// Registration is the registration flow the handlers call (TDD-02 §3): app.Registration.
type Registration interface {
	Start(ctx context.Context, cmd app.StartRegistration) (app.RegistrationStarted, error)
	VerifyCode(ctx context.Context, cmd app.VerifyRegistrationCode) (app.RegistrationProgress, error)
	Resend(ctx context.Context, cmd app.ResendRegistration) error
	ConfirmLink(ctx context.Context, cmd app.ConfirmLink) (app.LinkConfirmed, error)
}

// StartRegistration serves POST /v1/registrations.
func (a *API) StartRegistration(ctx context.Context, req gen.StartRegistrationRequestObject) (gen.StartRegistrationResponseObject, error) {
	if a.registration == nil {
		return nil, gen.ErrNotImplemented
	}
	b := req.Body
	s, err := a.registration.Start(ctx, app.StartRegistration{
		ClientID: b.ClientId, DisplayName: b.DisplayName, Locale: b.Locale, Identifiers: b.Identifiers,
		Password: []byte(b.Password), IP: clientip.From(ctx),
	})
	if err != nil {
		return nil, err
	}
	return gen.StartRegistration201JSONResponse{
		FlowId: s.FlowID, Handle: string(s.Handle), PendingTypes: s.PendingTypes, ExpiresAt: s.ExpiresAt,
	}, nil
}

// VerifyRegistrationCode serves POST /v1/registrations/{flowId}/verify.
func (a *API) VerifyRegistrationCode(ctx context.Context, req gen.VerifyRegistrationCodeRequestObject) (gen.VerifyRegistrationCodeResponseObject, error) {
	if a.registration == nil {
		return nil, gen.ErrNotImplemented
	}
	b := req.Body
	p, err := a.registration.VerifyCode(ctx, app.VerifyRegistrationCode{
		FlowID: req.FlowId, Handle: []byte(b.Handle), IdentifierType: b.IdentifierType, Code: []byte(b.Code),
		IP: clientip.From(ctx),
	})
	if err != nil {
		return nil, err
	}
	return gen.VerifyRegistrationCode200JSONResponse{PendingTypes: p.PendingTypes}, nil
}

// ResendRegistrationVerification serves POST /v1/registrations/{flowId}/resend.
func (a *API) ResendRegistrationVerification(ctx context.Context, req gen.ResendRegistrationVerificationRequestObject) (gen.ResendRegistrationVerificationResponseObject, error) {
	if a.registration == nil {
		return nil, gen.ErrNotImplemented
	}
	b := req.Body
	if err := a.registration.Resend(ctx, app.ResendRegistration{
		FlowID: req.FlowId, Handle: []byte(b.Handle), IdentifierType: b.IdentifierType, IP: clientip.From(ctx),
	}); err != nil {
		return nil, err
	}
	return gen.ResendRegistrationVerification202Response{}, nil
}

// ConfirmVerificationLink serves POST /v1/verification-links/confirm.
func (a *API) ConfirmVerificationLink(ctx context.Context, req gen.ConfirmVerificationLinkRequestObject) (gen.ConfirmVerificationLinkResponseObject, error) {
	if a.registration == nil {
		return nil, gen.ErrNotImplemented
	}
	c, err := a.registration.ConfirmLink(ctx, app.ConfirmLink{Token: []byte(req.Body.Token), IP: clientip.From(ctx)})
	if err != nil {
		return nil, err
	}
	pending := c.PendingTypes
	return gen.ConfirmVerificationLink200JSONResponse{
		Purpose: gen.LinkConfirmedPurpose(c.Purpose), FlowId: c.FlowID, Complete: c.Complete, PendingTypes: &pending,
	}, nil
}
