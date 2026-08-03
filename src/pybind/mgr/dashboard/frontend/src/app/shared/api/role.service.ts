import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { Observable, of as observableOf } from 'rxjs';
import { map, mergeMap } from 'rxjs/operators';

import { RoleFormModel } from '~/app/core/auth/role-form/role-form.model';
import { environment } from '~/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class RoleService {
  constructor(private http: HttpClient) {}

  list(): Observable<RoleFormModel[]> {
    return this.http.get<RoleFormModel[]>('api/role').pipe(
      map((roles) => {
        if (environment.build !== 'ibm') {
          return roles.filter((role) => role.name !== 'smb-manager');
        }
        return roles;
      })
    );
  }

  delete(name: string) {
    return this.http.delete(`api/role/${name}`);
  }

  get(name: string) {
    return this.http.get(`api/role/${name}`);
  }

  create(role: RoleFormModel) {
    return this.http.post(`api/role`, role);
  }

  clone(name: string, newName: string) {
    return this.http.post(`api/role/${name}/clone`, { new_name: newName });
  }

  update(role: RoleFormModel) {
    return this.http.put(`api/role/${role.name}`, role);
  }

  exists(name: string): Observable<boolean> {
    return this.list().pipe(
      mergeMap((roles: Array<RoleFormModel>) => {
        const exists = roles.some((currentRole: RoleFormModel) => {
          return currentRole.name === name;
        });
        return observableOf(exists);
      })
    );
  }
}
