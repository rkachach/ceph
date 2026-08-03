import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { environment } from '~/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ScopeService {
  constructor(private http: HttpClient) {}

  list(): Observable<string[]> {
    return this.http.get<string[]>('ui-api/scope').pipe(
      map((scopes) => {
        // SMB is an IBM-build-only feature (see app-routing.module.ts).
        if (environment.build !== 'ibm') {
          return scopes.filter((scope) => scope !== 'smb');
        }
        return scopes;
      })
    );
  }
}
