import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import _ from 'lodash';
import { Observable, of as observableOf } from 'rxjs';
import { catchError, mapTo } from 'rxjs/operators';

export interface ListenerRequest {
  host_name: string;
  traddr: string;
  trsvcid: number;
}

const BASE_URL = 'api/nvmeof';

@Injectable({
  providedIn: 'root'
})
export class NvmeofService {
  constructor(private http: HttpClient) {}

  listGateways() {
    return this.http.get(`${BASE_URL}/gateway`);
  }

  listSubsystems() {
    return this.http.get(`${BASE_URL}/subsystem`);
  }

  getSubsystem(subsystemNQN: string) {
    return this.http.get(`${BASE_URL}/subsystem/${subsystemNQN}`);
  }

  createSubsystem(request: { nqn: string; max_namespaces?: number; enable_ha: boolean }) {
    return this.http.post(`${BASE_URL}/subsystem`, request, { observe: 'response' });
  }

  deleteSubsystem(subsystemNQN: string) {
    return this.http.delete(`${BASE_URL}/subsystem/${subsystemNQN}`, {
      observe: 'response'
    });
  }

  isSubsystemPresent(subsystemNqn: string): Observable<boolean> {
    return this.getSubsystem(subsystemNqn).pipe(
      mapTo(true),
      catchError((e) => {
        e?.preventDefault();
        return observableOf(false);
      })
    );
  }

  // listeners
  listListeners(subsystemNQN: string) {
    return this.http.get(`${BASE_URL}/subsystem/${subsystemNQN}/listener`);
  }

  createListener(subsystemNQN: string, request: ListenerRequest) {
    return this.http.post(`${BASE_URL}/subsystem/${subsystemNQN}/listener`, request, {
      observe: 'response'
    });
  }

  deleteListener(subsystemNQN: string, hostName: string, traddr: string, trsvcid: string) {
    return this.http.delete(
      `${BASE_URL}/subsystem/${subsystemNQN}/listener/${hostName}/${traddr}`,
      {
        observe: 'response',
        params: {
          trsvcid
        }
      }
    );
  }
}
