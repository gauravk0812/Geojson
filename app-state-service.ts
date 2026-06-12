import { Injectable, Injector } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { IAuthResponse } from 'src/app/resources/auth-response';
import { IIpersionation } from 'src/app/resources/impersionation';
import { IRole } from 'src/app/resources/role';
import { IUser } from 'src/app/resources/user';
import {
  MANAGER_TITLES,
  STAFF_TITLES,
  TECHNICIAN_TITLES,
} from '../constants/app.constant';
import { BROADCAST_MESSAGES } from '../enums/broadcast-message.enum';
import { Utils } from '../utils/utils';
import { BroadcastService } from './broadcast.service';
import { BehaviorSubject, Observable } from 'rxjs';
import { ISite } from 'src/app/resources/site';

@Injectable()
export class AppStateService {
  private AUTH_DATA_KEY: string = 'authentication_data';
  private IMPERSONATION_DATA_KEY: string = 'impersonation_data';
  private POST_LOGIN_REDIRECT_KEY: string = 'post_login_redirect_url';
  private _authenticationData?: IAuthResponse;
  private _impersonationData?: IIpersionation;
  private _lastUserActivityAt: Date = new Date();
  private _currentUserPermissions: string[] = [];
  private staffTitle: string | null = null;
  private removedDefaultChipState = new Map<string, string[]>();
  private authStateSubject: BehaviorSubject<IAuthResponse | undefined> =
    new BehaviorSubject<IAuthResponse | undefined>(undefined);
  public authState$: Observable<IAuthResponse | undefined> =
    this.authStateSubject.asObservable();

  constructor(
    private broadcastService: BroadcastService,
    private injector: Injector
  ) {
    const authResponseStr = window.sessionStorage.getItem(this.AUTH_DATA_KEY);
    if (authResponseStr) {
      const authResponse = JSON.parse(authResponseStr);
      this.setAuthenticationData(authResponse);
    }

    const impersonationStr = window.sessionStorage.getItem(
      this.IMPERSONATION_DATA_KEY
    );
    if (impersonationStr) {
      try {
        this._impersonationData = JSON.parse(impersonationStr);
      } catch {
        window.sessionStorage.removeItem(this.IMPERSONATION_DATA_KEY);
      }
    }
  }

  public getSessionId(): string | undefined {
    return this._authenticationData?.session_id;
  }

  public getCurrentUser(): IUser | undefined {
    const currentUser = this._authenticationData?.user;
    if (!currentUser) {
      return undefined;
    }

    if (!this._impersonationData) {
      return currentUser;
    }

    const baseUser: IUser = currentUser;

    const impersonationPermissions =
      this._impersonationData.permissions ??
      this._impersonationData.assigned_permissions ??
      [];

    const impersonationRole: IRole = {
      id: this._impersonationData.user_id,
      name: this._impersonationData.title?.trim() || 'Impersonated User',
      description: '',
      assigned_permissions: [...impersonationPermissions],
      isSelected: false,
      sort_on: '',
      sort_ascending: true,
      search_text: '',
    };

    return {
      ...baseUser,
      id: this._impersonationData.user_id,
      user_name: this._impersonationData.user_name
        ? this._impersonationData.user_name
        : this._impersonationData.full_name
          ? this._impersonationData.full_name
          : `${this._impersonationData.first_name ?? ''} ${this._impersonationData.last_name ?? ''
            }`.trim() || currentUser.user_name,
      first_name: this._impersonationData.first_name ?? currentUser.first_name,
      last_name: this._impersonationData.last_name ?? currentUser.last_name,
      full_name: this._impersonationData.full_name
        ? this._impersonationData.full_name
        : `${this._impersonationData.first_name ?? ''} ${this._impersonationData.last_name ?? ''
          }`.trim() || currentUser.full_name,
      email: this._impersonationData.email ?? currentUser.email,
      tech_id: this._impersonationData.tech_id ?? currentUser.tech_id,
      staff_id: this._impersonationData.staff_id ?? currentUser.staff_id,
      title: this._impersonationData.title ?? currentUser.title,
      we_dist:
        this.normalizeStringArray(this._impersonationData.we_dist) ??
        currentUser.we_dist,
      wd_dist:
        this.normalizeStringArray(this._impersonationData.wd_dist) ??
        currentUser.wd_dist,
      roles: [impersonationRole],
      assigned_permissions: [...impersonationPermissions],
      user_type: this.resolveImpersonationUserType(
        this._impersonationData.title,
        currentUser.user_type
      ),
      is_admin: false,
      is_super_user: false,
    };
  }

  private normalizeStringArray(
    value: string | string[] | undefined
  ): string | undefined {
    return Array.isArray(value) ? value.join(', ') : value;
  }

  public getRefreshToken(): string | undefined {
    return this._authenticationData?.refresh_token;
  }

  public getAccessToken(): string | undefined {
    return this._authenticationData?.access_token;
  }

  public getTokenExpiryTime(): Date | undefined {
    return this._authenticationData?.expires_at;
  }

  public clearAuthenticationData(preservePostLoginRedirectUrl: boolean = false): void {
    this.closeOpenDialogs();
    sessionStorage.removeItem(this.AUTH_DATA_KEY);
    this._authenticationData = undefined;
    this.clearImpersonationDataInternal(false);
    if (!preservePostLoginRedirectUrl) {
      this.clearPostLoginRedirectUrl();
    }
    this._currentUserPermissions = [];
    this.clearRemovedDefaultChipState();
    this.authStateSubject.next(undefined);
    this.broadcastService.broadcast(BROADCAST_MESSAGES.USER_CHANGED);
  }

  public setPostLoginRedirectUrl(url: string | null | undefined): void {
    if (!this.isValidPostLoginRedirectUrl(url)) {
      this.clearPostLoginRedirectUrl();
      return;
    }

    sessionStorage.setItem(this.POST_LOGIN_REDIRECT_KEY, url.trim());
  }

  public getPostLoginRedirectUrl(): string | null {
    const redirectUrl = sessionStorage.getItem(this.POST_LOGIN_REDIRECT_KEY);
    return this.isValidPostLoginRedirectUrl(redirectUrl) ? redirectUrl : null;
  }

  public hasPostLoginRedirectUrl(): boolean {
    return this.getPostLoginRedirectUrl() !== null;
  }

  public hasExplicitQueryParameters(
    params: Record<string, unknown> | null | undefined,
    ignoredKeys: string[] = ['pg', 'pg-sz', 'q', 'sort_on', 'sort_dir']
  ): boolean {
    if (!params) {
      return false;
    }

    const ignored = new Set(ignoredKeys);
    return Object.keys(params).some((key) => {
      if (ignored.has(key)) {
        return false;
      }

      const value = params[key];
      if (Utils.isNullOrUndefined(value)) {
        return false;
      }

      if (typeof value === 'string') {
        return value.trim() !== '';
      }

      if (Array.isArray(value)) {
        return value.length > 0;
      }

      return true;
    });
  }

  public consumePostLoginRedirectUrl(defaultUrl: string = '/home'): string {
    const redirectUrl = this.getPostLoginRedirectUrl();
    this.clearPostLoginRedirectUrl();
    return redirectUrl ?? defaultUrl;
  }

  public clearPostLoginRedirectUrl(): void {
    sessionStorage.removeItem(this.POST_LOGIN_REDIRECT_KEY);
  }

  public setSessionExpiryWarningVisible(isVisible: boolean): void {
    this._isSessionExpiryWarningVisible = isVisible;
  }

  public isSessionExpiryWarningVisible(): boolean {
    return this._isSessionExpiryWarningVisible;
  }

  public setSessionExpiryLogoutInProgress(isInProgress: boolean): void {
    this._isSessionExpiryLogoutInProgress = isInProgress;
  }

  public isSessionExpiryLogoutInProgress(): boolean {
    return this._isSessionExpiryLogoutInProgress;
  }

  public setAuthenticationData(authenticationData: IAuthResponse) {
    if (Utils.isNullOrUndefined(authenticationData)) {
      this.closeOpenDialogs();
      sessionStorage.removeItem(this.AUTH_DATA_KEY);
      this._authenticationData = undefined; // ensure local cache cleared
      this.clearRemovedDefaultChipState();
      this.authStateSubject.next(this._authenticationData);
      this.broadcastService.broadcast(BROADCAST_MESSAGES.USER_CHANGED);
    } else {
      // Normalize expires_at to a Date instance (may be string when coming from JSON/sessionStorage)
      try {
        if (
          authenticationData &&
          (authenticationData as any).expires_at &&
          !(authenticationData.expires_at instanceof Date)
        ) {
          authenticationData.expires_at = new Date(
            (authenticationData as any).expires_at
          ) as any;
        }
      } catch {
        /* swallow parse errors; downstream code will handle invalid date */
      }
      sessionStorage.setItem(
        this.AUTH_DATA_KEY,
        JSON.stringify(authenticationData)
      );
      this._authenticationData = authenticationData;
      this.authStateSubject.next(this._authenticationData); // emit latest auth state
      this.broadcastService.broadcast(BROADCAST_MESSAGES.USER_CHANGED);
    }
  }

  public getImpersonationData(): IIpersionation | undefined {
    return this._impersonationData;
  }

  public isImpersonating(): boolean {
    return !Utils.isNullOrUndefined(this._impersonationData);
  }

  public getImpersonationDisplayName(): string {
    const impersonation = this._impersonationData;
    if (!impersonation) {
      return '';
    }

    const displayName =
      impersonation.full_name ??
      `${impersonation.first_name ?? ''} ${impersonation.last_name ?? ''} ${impersonation.tech_id ?? ''}`.trim()
    return impersonation.title
      ? `${displayName} - ${impersonation.title}`
      : displayName;
  }

  public getImpersonatedUserId(): string | undefined {
    return this._impersonationData?.user_id;
  }

  public getAuthenticatedUser(): IUser | undefined {
    return this._authenticationData?.user;
  }

  public recordUserActivity(activityAt: Date = new Date()): void {
    this._lastUserActivityAt = activityAt;
  }

  public getLastUserActivityAt(): Date {
    return this._lastUserActivityAt;
  }

  public setImpersonationData(impersonationData: IIpersionation | null): void {
    if (!impersonationData) {
      this.clearImpersonationData();
      return;
    }

    if (!impersonationData.session_started_at) {
      impersonationData.session_started_at = new Date().toISOString();
    }

    this._impersonationData = impersonationData;
    sessionStorage.setItem(
      this.IMPERSONATION_DATA_KEY,
      JSON.stringify(impersonationData)
    );
    this.broadcastService.broadcast(BROADCAST_MESSAGES.USER_CHANGED);
  }

  public clearImpersonationData(): void {
    this.clearImpersonationDataInternal(true);
  }

  public isUserLoggedIn(): boolean {
    let currentUser: IUser | undefined = this.getCurrentUser();
    return !Utils.isNullOrUndefined(currentUser);
  }

  public getCurrentUserPermissions(): string[] | [] {
    return this._currentUserPermissions;
  }

  public setCurrentUserPermissions(permissions: string[]) {
    this._currentUserPermissions = permissions;
  }

  public hasPermission(permission: string): boolean {
    let currentUser: IUser | undefined = this.getCurrentUser();
    if (Utils.isNullOrUndefined(currentUser)) return false;

    if (currentUser?.is_admin || currentUser?.is_super_user) return true;

    const allPermissions = this.getAllUserPermissions();
    return (
      allPermissions.includes(permission) ||
      this._currentUserPermissions.includes(permission)
    );
  }

  /**
   * This is used to set staff title
   * @param title
   */
  setStaffTitle(title: string): void {
    this.staffTitle = title;
  }

  getStaffTitle(): string | null {
    return this.staffTitle;
  }

  public isTechnicianTitle(title?: string | null): boolean {
    if (!title) {
      return false;
    }

    return TECHNICIAN_TITLES.includes(
      title as (typeof TECHNICIAN_TITLES)[number]
    );
  }

  /**
   * Get all permissions for the current user
   */
  private getAllUserPermissions(): string[] {
    const user = this.getCurrentUser();
    return user?.roles.map((role) => role.assigned_permissions).flat() || [];
  }

  /**
   * Check if user has a specific permission
   * @param permission - The permission string to check
   * @returns boolean - true if user has the permission
   */
  hasUserPermission(permission: string): boolean {
    const allPermissions = this.getAllUserPermissions();
    return allPermissions.includes(permission);
  }

  /**
   * Check if user has any of the specified permissions
   * @param permissions - Array of permission strings to check
   * @returns boolean - true if user has at least one of the permissions
   */
  hasAnyPermission(permissions: string[]): boolean {
    const allPermissions = this.getAllUserPermissions();
    return permissions.some((permission) =>
      allPermissions.includes(permission)
    );
  }

  /**
   * Check if user has all of the specified permissions
   * @param permissions - Array of permission strings to check
   * @returns boolean - true if user has all of the permissions
   */
  hasAllPermissions(permissions: string[]): boolean {
    const allPermissions = this.getAllUserPermissions();
    return permissions.every((permission) =>
      allPermissions.includes(permission)
    );
  }

  private selectedSiteSubject = new BehaviorSubject<ISite | null>(null);
  public selectedSite$ = this.selectedSiteSubject.asObservable();

  // Check-in status tracking - single source of truth
  private isCheckedInSubject = new BehaviorSubject<boolean>(false);
  public isCheckedIn$ = this.isCheckedInSubject.asObservable();

  // Track the site user is checked into (separate from selected site)
  private checkedInSiteSubject = new BehaviorSubject<ISite | null>(null);
  public checkedInSite$ = this.checkedInSiteSubject.asObservable();

  setSelectedSite(site: ISite | null): void {
    this.selectedSiteSubject.next(site);
  }

  getSelectedSite(): ISite | null {
    return this.selectedSiteSubject.value;
  }

  clearSelectedSite(): void {
    this.selectedSiteSubject.next(null);
  }

  /**
   * Set the check-in status - should only be called from AppComponent
   */
  setIsCheckedIn(isCheckedIn: boolean): void {
    this.isCheckedInSubject.next(isCheckedIn);
    // If checking out, clear the checked-in site
    if (!isCheckedIn) {
      this.checkedInSiteSubject.next(null);
    }
  }

  /**
   * Get current check-in status synchronously
   */
  getIsCheckedIn(): boolean {
    return this.isCheckedInSubject.value;
  }

  /**
   * Set the site user is checked into
   */
  setCheckedInSite(site: ISite | null): void {
    this.checkedInSiteSubject.next(site);
  }

  /**
   * Get the site user is checked into synchronously
   */
  getCheckedInSite(): ISite | null {
    return this.checkedInSiteSubject.value;
  }

  /**
   * Get the active site for filtering purposes.
   * Priority: selected site > checked-in site
   * This should be used by list components to filter data by site.
   */
  getActiveFilterSite(): ISite | null {
    // Selected site takes priority over checked-in site
    const selectedSite = this.getSelectedSite();
    if (selectedSite) {
      return selectedSite;
    }
    return this.getCheckedInSite();
  }

  /**
   * Observable for active filter site changes.
   * Emits when either checked-in site or selected site changes.
   */
  get activeFilterSite$(): Observable<ISite | null> {
    return new Observable<ISite | null>((subscriber) => {
      // Combine both observables, prioritizing checked-in site
      const updateValue = () => {
        subscriber.next(this.getActiveFilterSite());
      };

      const checkedInSub = this.checkedInSite$.subscribe(() => updateValue());
      const selectedSub = this.selectedSite$.subscribe(() => updateValue());

      // Emit initial value
      updateValue();

      return () => {
        checkedInSub.unsubscribe();
        selectedSub.unsubscribe();
      };
    });
  }

  setRemovedDefaultChips(storageKey: string, chips: Iterable<string>): void {
    if (Utils.isEmptyOrWhiteSpace(storageKey)) {
      return;
    }

    const normalizedChips = Array.from(
      new Set(
        Array.from(chips).filter(
          (chip) => typeof chip === 'string' && !Utils.isEmptyOrWhiteSpace(chip)
        )
      )
    );

    if (normalizedChips.length === 0) {
      this.removedDefaultChipState.delete(storageKey);
      return;
    }

    this.removedDefaultChipState.set(storageKey, normalizedChips);
  }

  getRemovedDefaultChips(storageKey: string): string[] {
    if (Utils.isEmptyOrWhiteSpace(storageKey)) {
      return [];
    }

    const removedChips = this.removedDefaultChipState.get(storageKey);
    return removedChips ? [...removedChips] : [];
  }

  clearRemovedDefaultChipState(storageKey?: string): void {
    if (!storageKey || Utils.isEmptyOrWhiteSpace(storageKey)) {
      this.removedDefaultChipState.clear();
      return;
    }

    this.removedDefaultChipState.delete(storageKey);
  }

  private closeOpenDialogs(): void {
    try {
      this.injector.get(MatDialog).closeAll();
    } catch {
      // Ignore if MatDialog is not available during app bootstrap/teardown.
    }
  }

  private clearImpersonationDataInternal(shouldBroadcast: boolean): void {
    sessionStorage.removeItem(this.IMPERSONATION_DATA_KEY);
    this._impersonationData = undefined;

    if (shouldBroadcast) {
      this.broadcastService.broadcast(BROADCAST_MESSAGES.USER_CHANGED);
    }
  }

  private _isSessionExpiryWarningVisible = false;
  private _isSessionExpiryLogoutInProgress = false;

  private resolveImpersonationUserType(
    title: string | undefined,
    fallbackUserType: string | undefined
  ): string {
    if (!title) {
      return fallbackUserType ?? '';
    }

    if (TECHNICIAN_TITLES.includes(title as (typeof TECHNICIAN_TITLES)[number])) {
      return 'STAFF';
    }

    if (MANAGER_TITLES.includes(title as (typeof MANAGER_TITLES)[number])) {
      return 'LEADERSHIP';
    }

    return fallbackUserType ?? '';
  }

  private isValidPostLoginRedirectUrl(
    url: string | null | undefined
  ): url is string {
    if (!url) {
      return false;
    }

    const normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('/') || normalizedUrl.startsWith('//')) {
      return false;
    }

    return !['/login', '/saml', '/not-authorized'].some(
      (blockedPath) =>
        normalizedUrl === blockedPath ||
        normalizedUrl.startsWith(`${blockedPath}?`) ||
        normalizedUrl.startsWith(`${blockedPath}#`) ||
        normalizedUrl.startsWith(`${blockedPath}/`)
    );
  }
}
