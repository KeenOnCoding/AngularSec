import { Component, OnInit } from '@angular/core';
import {
  AuthenticatedResult,
  OidcClientNotification,
  OpenIdConfiguration,
  UserDataResult,
} from 'angular-auth-oidc-client';
import { Observable } from 'rxjs';
import { AuthorizeService } from '../services/authorize-service.service';

@Component({
  selector: 'app-home',
  templateUrl: 'home.component.html',
})
export class HomeComponent implements OnInit {
  configurations: OpenIdConfiguration[];

  userDataChanged$: Observable<OidcClientNotification<any>>;

  userData$: Observable<UserDataResult>;

  isAuthenticated$: Observable<AuthenticatedResult>;


  constructor(public authorize: AuthorizeService) { }

  ngOnInit(): void {
    this.configurations = this.authorize.configurations;
    this.userData$ = this.authorize.userData$;
    this.isAuthenticated$ = this.authorize.isAuthenticated$;
  }



  login(configId: string) {
    this.authorize.login(configId);
  }

  forceRefreshSession() {
    this.authorize
      .forceRefreshSession();
    //.subscribe((result) => console.warn(result));
  }

  logout(configId: string) {
    this.authorize
      .logout(configId);
    //.subscribe((result) => console.log(result));
  }

  refreshSessionId4(configId: string) {
    this.authorize
      .refreshSessionId4(configId);
    //.subscribe((result) => console.log(result));
  }

  refreshSessionAuth0(configId: string) {
    this.authorize
      .refreshSessionAuth0(configId);
    //.forceRefreshSession(
    //  { scope: 'openid profile offline_access auth0-user-api-spa' },
    //  configId
    //)
    //.subscribe((result) => console.log(result));
  }

  logoffAndRevokeTokens(configId: string) {
    this.authorize
      .logoffAndRevokeTokens(configId);
    //.subscribe((result) => console.log(result));
  }

  revokeRefreshToken(configId: string) {
    this.authorize
      .revokeRefreshToken(configId);
    //.subscribe((result) => console.log(result));
  }
}
