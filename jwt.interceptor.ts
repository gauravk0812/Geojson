import {
  HttpErrorResponse,
  HttpEvent,
  HttpHandler,
  HttpInterceptor,
  HttpRequest,
} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, throwError } from 'rxjs';
import { AppStateService } from './app-state-service';
import { Router } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { AlertDialogComponent } from '../components/alert-dialog/alert-dialog.component';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
  private isShowingLockedSessionDialog = false;
  private isShowingImpersonationSessionDialog = false;

  constructor(
    private appStateService: AppStateService,
    private router: Router,
    private dialog: MatDialog
  ) {}

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const moduleName = this.getModuleName();

    request = request.clone({
      setHeaders: {
        'X-Module_Name': moduleName,
      },
    });

    // Always fetch the latest token before making the request
    const isLoggedIn = this.appStateService.isUserLoggedIn();
    if (isLoggedIn) {
      this.appStateService.recordUserActivity();

      // user is logged-in, add authorization header
      let access_token: string = this.appStateService.getAccessToken() || '';
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${access_token}`,
        },
      });
    }

    const impersonatedUserId = this.appStateService.getImpersonatedUserId();
    if (impersonatedUserId && !this.isImpersonationStopRequest(request)) {
      request = request.clone({
        setHeaders: {
          'X-Impersonate-User': impersonatedUserId,
        },
      });
    }

    // if we are reaching here, then either the user is not logged-in
    // or the token is not yet close to expiry
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          if (this.appStateService.isSessionExpiryLogoutInProgress()) {
            return throwError(error);
          }

          const currentUrl =
            this.router.url && this.router.url !== '/'
              ? this.router.url
              : `${window.location.pathname}${window.location.search}${window.location.hash}`;
          this.appStateService.setPostLoginRedirectUrl(currentUrl);
          this.appStateService.clearAuthenticationData(true);
          this.router.navigate(['/login']);
        }

        if (error.status === 423) {
          if (!this.shouldSuppressSessionDialogs()) {
            this.handleLockedSession(error);
          }
        }

        if (error.status === 424) {
          if (!this.shouldSuppressSessionDialogs()) {
            this.handleImpersonationSessionExpired(error);
          }
        }

        return throwError(error);
      })
    );
  }

  private handleLockedSession(error: HttpErrorResponse): void {
    if (this.isShowingLockedSessionDialog) {
      return;
    }

    this.isShowingLockedSessionDialog = true;
    const dialogRef = this.dialog.open(AlertDialogComponent, {
      data: {
        title: 'Session Locked',
        message: this.getErrorMessage(error),
        okText: 'OK',
      },
      width: '420px',
      disableClose: true,
    });

    dialogRef.afterClosed().subscribe(() => {
      this.isShowingLockedSessionDialog = false;
      this.appStateService.clearAuthenticationData();
      this.router.navigate(['/login']);
    });
  }

  private handleImpersonationSessionExpired(error: HttpErrorResponse): void {
    if (this.isShowingImpersonationSessionDialog) {
      return;
    }    

    this.isShowingImpersonationSessionDialog = true;
    const dialogRef = this.dialog.open(AlertDialogComponent, {
      data: {
        title: 'Impersonation Session Ended',
        message: this.getErrorMessage(
          error,
          error.error.detail 
        ),
        okText: 'OK',
      },
      width: '420px',
      disableClose: true,
    });

    dialogRef.afterClosed().subscribe(() => {
      this.isShowingImpersonationSessionDialog = false;
      this.appStateService.clearImpersonationData();
      this.router.navigate(['/home']);
    });
  }

  private isImpersonationStopRequest(request: HttpRequest<any>): boolean {
    const normalizedUrl = request.url.toLowerCase();
    return normalizedUrl.includes('/impersonate/') && normalizedUrl.endsWith('/stop');
  }

  private getErrorMessage(
    error: HttpErrorResponse,
    fallbackMessage: string = 'Your session is locked. Please log in again.'
  ): string {
    const responseBody = error.error;

    if (typeof responseBody === 'string' && responseBody.trim()) {
      return responseBody;
    }

    const responseMessage =
      responseBody?.message ||
      responseBody?.errorMessage ||
      responseBody?.detail;

    if (typeof responseMessage === 'string' && responseMessage.trim()) {
      return responseMessage;
    }

    return fallbackMessage;
  }

  private getModuleName(): string {
    const currentUrl =
      this.router.url && this.router.url !== '/'
        ? this.router.url
        : `${window.location.pathname}${window.location.search}${window.location.hash}`;

    const normalizedPath = currentUrl.split('?')[0].split('#')[0];
    const firstSegment = normalizedPath.split('/').filter(Boolean)[0];

    if (firstSegment) {
      return firstSegment;
    }

    return 'login';
  }

  private shouldSuppressSessionDialogs(): boolean {
    return (
      this.appStateService.isSessionExpiryWarningVisible() ||
      this.appStateService.isSessionExpiryLogoutInProgress()
    );
  }
}
