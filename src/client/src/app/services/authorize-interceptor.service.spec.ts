import { TestBed } from '@angular/core/testing';

import { AuthorizeInterceptor } from './authorize-interceptor.service';

describe('AuthorizeInterceptor', () => {
  let service: AuthorizeInterceptor;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthorizeInterceptor);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
