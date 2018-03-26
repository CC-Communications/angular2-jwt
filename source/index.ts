import { NgModule, ModuleWithProviders, Optional, SkipSelf, Provider } from '@angular/core';
import { JwtInterceptor } from './src/jwt.interceptor';
import { JwtHelperService } from './src/jwthelper.service';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { JWT_OPTIONS } from './src/jwtoptions.token';
import { Observable } from 'rxjs/Observable';

export * from './src/jwt.interceptor';
export * from './src/jwthelper.service';
export * from './src/jwtoptions.token';

export interface JwtModuleOptions {
  jwtOptionsProvider?: Provider,
  config?: {
    tokenGetter?: () => string | Promise<string>;
    headerName?: string;
    authScheme?: string;
    whitelistedDomains?: Array<string | RegExp>;
    throwNoTokenError?: boolean;
    skipWhenExpired?: boolean;
    beforeRefreshSeconds: number; // check to see if the token expires soon and go ahead and refresh
    tokenRefresher?: ()=> Observable<string>;
  }
}

@NgModule()
export class JwtModule {

  constructor(@Optional() @SkipSelf() parentModule: JwtModule) {
    if (parentModule) {
      throw new Error('JwtModule is already loaded. It should only be imported in your application\'s main module.');
    }
  }
  static forRoot(options: JwtModuleOptions): ModuleWithProviders {
    return {
      ngModule: JwtModule,
      providers: [
        {
          provide: HTTP_INTERCEPTORS,
          useClass: JwtInterceptor,
          multi: true
        },
        options.jwtOptionsProvider ||
        {
          provide: JWT_OPTIONS,
          useValue: options.config
        },
        JwtHelperService
      ]
    };
  }
}
