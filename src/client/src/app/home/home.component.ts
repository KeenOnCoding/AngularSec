import { HttpClient, HttpHeaders, HttpRequest } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import {
  AuthenticatedResult,
  OidcClientNotification,
  OpenIdConfiguration,
  UserDataResult,
} from 'angular-auth-oidc-client';
import { Observable } from 'rxjs';
import { AuthorizeService } from '../services/authorize-service.service';
interface WeatherForecast {
  date: string;
  temperatureC: number;
  temperatureF: number;
  summary: string;
}
@Component({
  selector: 'app-home',
  templateUrl: 'home.component.html',
})
export class HomeComponent implements OnInit {
  configurations: OpenIdConfiguration[];

  userDataChanged$: Observable<OidcClientNotification<any>>;

  userData$: Observable<UserDataResult>;

  isAuthenticated$: Observable<AuthenticatedResult>;

  public forecasts: WeatherForecast[] = [];

  constructor(private http: HttpClient, public authorize: AuthorizeService) { }

  ngOnInit(): void {
    this.configurations = this.authorize.configurations;
    this.userData$ = this.authorize.userData$;
    this.isAuthenticated$ = this.authorize.isAuthenticated$;

  }

  getData() {
    //this.http.get<any>("https://localhost:44305/" + 'weatherforecast')
    //.subscribe(result => { console.log('RESULT   ' + result); }, error => console.error(error));
    this.http.request(
      new HttpRequest<WeatherForecast[]>('GET',
        "https://localhost:44305/" + 'weatherforecast',
        null,
        { responseType: 'json', }))
      .subscribe(result =>
      { console.log(result) },
        error => console.error(error));
    console.log(this.forecasts);
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
