import { Injectable, Inject } from "@angular/core";
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from "@angular/common/http";
import { JwtHelperService } from "./jwthelper.service";
import { JWT_OPTIONS } from "./jwtoptions.token";
import { Observable } from "rxjs/Observable";
import { BehaviorSubject } from "rxjs/BehaviorSubject";
import { _throw } from "rxjs/observable/throw";
import { mergeMap, switchMap, filter, take } from "rxjs/operators";

import "rxjs/add/observable/fromPromise";
import "rxjs/add/operator/catch";
import "rxjs/add/operator/finally";
var url = require("url");

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
  tokenGetter: () => string | Promise<string>;
  headerName: string;
  authScheme: string;
  whitelistedDomains: Array<string | RegExp>;
  throwNoTokenError: boolean;
  skipWhenExpired: boolean;
  beforeRefreshSeconds: number; // check to see if the token expires soon and go ahead and refresh
  tokenRefresher?: () => Observable<string>;

  constructor(
    @Inject(JWT_OPTIONS) config: any,
    public jwtHelper: JwtHelperService
  ) {
    this.tokenGetter = config.tokenGetter;
    this.headerName = config.headerName || "Authorization";
    this.authScheme =
      config.authScheme || config.authScheme === ""
        ? config.authScheme
        : "Bearer ";
    this.whitelistedDomains = config.whitelistedDomains || [];
    this.throwNoTokenError = config.throwNoTokenError || false;
    this.skipWhenExpired = config.skipWhenExpired;
    this.beforeRefreshSeconds = config.beforeRefreshSeconds;
    this.tokenRefresher = config.tokenRefresher;
  }

  isWhitelistedDomain(request: HttpRequest<any>): boolean {
    const requestUrl = url.parse(request.url);

    return (
      this.whitelistedDomains.findIndex(
        domain =>
          typeof domain === "string"
            ? domain === requestUrl.host
            : domain instanceof RegExp
              ? domain.test(requestUrl.host)
              : false
      ) > -1
    );
  }

  isRefreshingToken: boolean = false;
  tokenSubject: BehaviorSubject<string> = new BehaviorSubject<string>(null);

  refreshToken(req: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshingToken) {
      this.isRefreshingToken = true;

      this.tokenSubject.next(null);

      return this.tokenRefresher()
        .pipe(
          switchMap((newToken: string) => {
            if (newToken) {
              this.tokenSubject.next(newToken);
              return next.handle(this.addToken(req, newToken));
            }
            return _throw("We did not receive a new token on refresh");
          })
        )
        .catch(error => {
          return _throw(error);
        })
        .finally(() => {
          this.isRefreshingToken = false;
        });
    } else {
      return this.tokenSubject.pipe(
        filter(token => token != null),
        take(1),
        switchMap(token => {
          return next.handle(this.addToken(req, token));
        })
      );
    }
  }
  addToken(request: HttpRequest<any>, token: string): HttpRequest<any> {
    return request.clone({
      setHeaders: {
        [this.headerName]: `${this.authScheme}${token}`
      }
    });
  }
  handleInterception(
    token: string,
    request: HttpRequest<any>,
    next: HttpHandler
  ) {
    let tokenIsExpired: boolean;
    let doRefresh: boolean = this.tokenRefresher != null;

    if (!token && this.throwNoTokenError) {
      return _throw("Could not get token from tokenGetter function.");
    }

    if (this.skipWhenExpired || doRefresh) {
      // if refresh is enabled, offset the expiration by X seconds so we can go ahead and do our refres out
      tokenIsExpired = token
        ? this.jwtHelper.isTokenExpired(
            token,
            doRefresh ? this.beforeRefreshSeconds : null
          )
        : true;
    }

    if (doRefresh && tokenIsExpired && this.isWhitelistedDomain(request)) {
      return this.refreshToken(request, next);
    } else {
      if (token && tokenIsExpired && this.skipWhenExpired) {
        request = request.clone();
      } else if (token && this.isWhitelistedDomain(request)) {
        request = this.addToken(request, token);
      }
      return next.handle(request).catch(error => {
        if (
          error instanceof HttpErrorResponse &&
          this.isWhitelistedDomain(request)
        ) {
          switch ((<HttpErrorResponse>error).status) {
            case 401:
              return this.refreshToken(request, next);
            default:
              return _throw(error);
          }
        } else {
          return _throw(error);
        }
      });
    }
  }

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token: any = this.tokenGetter();

    if (token instanceof Promise) {
      return Observable.fromPromise(token).pipe(
        mergeMap((asyncToken: string) => {
          return this.handleInterception(asyncToken, request, next);
        })
      );
    } else {
      return this.handleInterception(token, request, next);
    }
  }
}
