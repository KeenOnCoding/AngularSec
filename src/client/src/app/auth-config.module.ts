import { NgModule } from '@angular/core';
import { AuthModule, LogLevel } from 'angular-auth-oidc-client';
// https://angular-auth-oidc-client.com/docs/samples/
@NgModule({
  imports: [
    AuthModule.forRoot({
      config: [
        {
          authority: 'https://localhost:44305',
          
          redirectUrl: window.location.origin,
          postLogoutRedirectUri: window.location.origin,
          clientId: 'FreeFile-FE',
          scope: 'openid profile vacancy',
          responseType: 'code',
          silentRenew: true,
          useRefreshToken: true,
          secureRoutes: ['https://localhost:44305/','https://localhost:7129/'],
          customParamsAuthRequest: {
            audience: 'https://localhost:7129/',
          },
          logLevel: LogLevel.Debug
        },
        {
          authority: 'https://dev-damienbod.eu.auth0.com',
          redirectUrl: window.location.origin,
          postLogoutRedirectUri: window.location.origin,
          clientId: 'Ujh5oSBAFr1BuilgkZPcMWEgnuREgrwU',
          scope: 'openid profile offline_access auth0-user-api-spa',
          responseType: 'code',
          silentRenew: true,
          useRefreshToken: true,
          logLevel: LogLevel.Debug,
          
          customParamsAuthRequest: {
            audience: 'https://auth0-api-spa',
          },
          customParamsRefreshTokenRequest: {
            scope: 'openid profile offline_access auth0-user-api-spa',
          },
        },
      ],
    }),
  ],
  exports: [AuthModule],
})
export class AuthConfigModule {}
