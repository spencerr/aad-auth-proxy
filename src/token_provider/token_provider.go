package token_provider

import (
	"aad-auth-proxy/constants"
	"aad-auth-proxy/contracts"
	"aad-auth-proxy/utils"
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type tokenProvider struct {
	token                            string
	ctx                              context.Context
	lastError                        error
	userConfiguredDurationPercentage uint8
	refreshDuration                  time.Duration
	credentialClient                 azcore.TokenCredential
	options                          *policy.TokenRequestOptions
}

func NewTokenProvider(audience string, config utils.IConfiguration, logger contracts.ILogger) (contracts.ITokenProvider, error) {
	if config == nil || logger == nil {
		return nil, errors.New("NewTokenProvider: Required arguments canot be nil")
	}

	userConfiguredDurationPercentage := config.GetAadTokenRefreshDurationInPercentage()

	cred, err := azidentity.NewDefaultAzureCredential(nil)

	if err != nil {
		return nil, err
	}

	tokenProvider := &tokenProvider{
		ctx:                              context.Background(),
		token:                            "",
		lastError:                        nil,
		userConfiguredDurationPercentage: userConfiguredDurationPercentage,
		credentialClient:                 cred,
		options:                          &policy.TokenRequestOptions{Scopes: []string{audience}},
	}

	err = tokenProvider.refreshAADToken()
	if err != nil {
		return nil, errors.New("Failed to get access token: " + err.Error())
	}

	go tokenProvider.periodicallyRefreshClientToken(logger)
	return tokenProvider, nil
}

func (tokenProvider *tokenProvider) GetAccessToken() (string, error) {
	return tokenProvider.token, tokenProvider.lastError
}

func (tokenProvider *tokenProvider) refreshAADToken() error {
	// Record traces
	ctx, span := otel.Tracer(constants.SERVICE_TELEMETRY_KEY).Start(tokenProvider.ctx, "refreshAADToken")
	defer span.End()

	// Telemetry attributes
	attributes := []attribute.KeyValue{}

	// Record metrics
	// token_refresh_total{is_success}
	meter := otel.Meter(constants.SERVICE_TELEMETRY_KEY)
	intrument, _ := meter.Int64Counter(constants.METRIC_TOKEN_REFRESH_TOTAL)

	accessToken, err := tokenProvider.credentialClient.GetToken(ctx, *tokenProvider.options)
	if err != nil {
		attributes = append(attributes, attribute.Bool("is_success", false))
		span.SetAttributes(attributes...)
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to refresh token")
		intrument.Add(ctx, 1)

		// Set last error so that this can be returned back when the token is requested
		tokenProvider.lastError = err

		return err
	}

	// Reset last error
	tokenProvider.lastError = nil

	attributes = append(attributes, attribute.Bool("is_success", true))
	intrument.Add(ctx, 1)

	tokenProvider.setToken(ctx, accessToken.Token)
	tokenProvider.updateRefreshDuration(accessToken)

	attributes = append(attributes,
		attribute.String("token.expiry_timestamp", accessToken.ExpiresOn.UTC().String()),
		attribute.String("tokenrefresh.next_refresh_timestamp", time.Now().Add(tokenProvider.refreshDuration).UTC().String()),
		attribute.String("tokenrefresh.refresh_duration", tokenProvider.refreshDuration.String()),
	)
	span.SetAttributes(attributes...)
	return nil
}

func (tokenProvider *tokenProvider) periodicallyRefreshClientToken(logger contracts.ILogger) error {
	defer utils.HandlePanic("periodicallyRefreshClientToken")

	for {
		select {
		case <-tokenProvider.ctx.Done():
			return nil
		case <-time.After(tokenProvider.refreshDuration):
			err := tokenProvider.refreshAADToken()
			if err != nil {
				tokenProvider.refreshDuration = time.Duration(constants.TIME_5_MINUTES)
				logger.Error("Failed to refresh token, retry in 5 minutes", err)
				return errors.New("Failed to refresh token: " + err.Error())
			}
		}
	}
}

func (tokenProvider *tokenProvider) setToken(ctx context.Context, token string) {
	var V atomic.Value
	V.Store(token)
	tokenProvider.token = V.Load().(string)
}

func (tokenProvider *tokenProvider) updateRefreshDuration(accessToken azcore.AccessToken) error {
	earlistTime := tokenProvider.getRefreshDuration(accessToken)
	tokenProvider.refreshDuration = earlistTime.Sub(time.Now().UTC())
	return nil
}

func (tokenProvider *tokenProvider) getRefreshDuration(accessToken azcore.AccessToken) time.Time {
	tokenExpiryTimestamp := accessToken.ExpiresOn.UTC()
	userConfiguredTimeFromNow := time.Now().UTC().Add(time.Duration(100-tokenProvider.userConfiguredDurationPercentage) * accessToken.ExpiresOn.Sub(time.Now()) / 100)
	// 10 seconds before now
	thresholdTimestamp := time.Now().UTC().Add(-10 * time.Second)

	// Some times the token expiry time is less than 10 seconds from now or we received an expired token.
	// In that case, we will refresh the token in 1 minute.
	if userConfiguredTimeFromNow.Before(thresholdTimestamp) {
		return time.Now().UTC().Add(constants.TIME_1_MINUTES)
	} else if userConfiguredTimeFromNow.Before(tokenExpiryTimestamp) {
		// If the user configured time is less than the token expiry time, we will use the user configured time.
		return userConfiguredTimeFromNow
	} else {
		return time.Now().UTC().Add(constants.TIME_1_MINUTES)
	}
}
