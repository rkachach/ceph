import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterTestingModule } from '@angular/router/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ToastrModule } from 'ngx-toastr';
import { NgbActiveModal, NgbTypeaheadModule } from '@ng-bootstrap/ng-bootstrap';

import { SharedModule } from '~/app/shared/shared.module';
import { NvmeofService } from '~/app/shared/api/nvmeof.service';
import { NvmeofListenersFormComponent } from './nvmeof-listeners-form.component';

describe('NvmeofListenersFormComponent', () => {
  let component: NvmeofListenersFormComponent;
  let fixture: ComponentFixture<NvmeofListenersFormComponent>;
  let nvmeofService: NvmeofService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [NvmeofListenersFormComponent],
      providers: [NgbActiveModal],
      imports: [
        HttpClientTestingModule,
        NgbTypeaheadModule,
        ReactiveFormsModule,
        RouterTestingModule,
        SharedModule,
        ToastrModule.forRoot()
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(NvmeofListenersFormComponent);
    component = fixture.componentInstance;
    component.ngOnInit();
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('should test form', () => {
    beforeEach(() => {
      nvmeofService = TestBed.inject(NvmeofService);
      spyOn(nvmeofService, 'createListener').and.stub();
    });
  });
});
