import { Component, OnInit } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { Observable } from 'rxjs';

import { Icons } from '~/app/shared/enum/icons.enum';
import { Permission } from '~/app/shared/models/permissions';
import { ActionLabelsI18n } from '~/app/shared/constants/app.constants';
import { AuthStorageService } from '~/app/shared/services/auth-storage.service';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { UpgradeService } from '~/app/shared/api/upgrade.service';
import { UpgradeInfoInterface } from '~/app/shared/models/upgrade.interface';
import { NotificationType } from '~/app/shared/enum/notification-type.enum';
import { CdFormGroup } from '~/app/shared/forms/cd-form-group';
import { NotificationService } from '~/app/shared/services/notification.service';
import { LicenceAgreementComponent } from '../../license-agreement/license-agreement.component';
import { ModalCdsService } from '~/app/shared/services/modal-cds.service';
import { ClusterService } from '~/app/shared/api/cluster.service';

@Component({
  selector: 'cd-upgrade-start-modal.component',
  templateUrl: './upgrade-start-modal.component.html',
  styleUrls: ['./upgrade-start-modal.component.scss'],
  standalone: false
})
export class UpgradeStartModalComponent implements OnInit {
  permission: Permission;
  upgradeInfoError$: Observable<any>;
  upgradeInfo$: Observable<UpgradeInfoInterface>;
  upgradeForm: CdFormGroup;
  icons = Icons;
  versions: string[];
  licenseAccepted = false;

  showImageField = false;
  imageFetchError = false;
  imageFetchErrorMessage = '';

  constructor(
    public actionLabels: ActionLabelsI18n,
    private authStorageService: AuthStorageService,
    public activeModal: NgbActiveModal,
    private upgradeService: UpgradeService,
    private notificationService: NotificationService,
    private modalCdsService: ModalCdsService,
    private clusterService: ClusterService
  ) {
    this.permission = this.authStorageService.getPermissions().configOpt;
  }

  ngOnInit() {
    this.upgradeForm = new CdFormGroup({
      availableVersions: new FormControl(null, [Validators.required]),
      useImage: new FormControl(false),
      customImageName: new FormControl(null)
    });
    if (this.versions === undefined) {
      const availableVersionsControl = this.upgradeForm.get('availableVersions');
      availableVersionsControl.clearValidators();
      const customImageNameControl = this.upgradeForm.get('customImageName');
      customImageNameControl.setValidators(Validators.required);
      customImageNameControl.updateValueAndValidity();
    }
  }

  showLicenceAgreement() {
    const customImageName = this.upgradeForm.getValue('customImageName');

    // Clear previous error
    this.imageFetchError = false;
    this.imageFetchErrorMessage = '';

    // Validate image by fetching license first
    this.clusterService.getLicense(customImageName).subscribe({
      next: (licenseData: { call_home_notice: string; license: string }) => {
        // Image is valid, open license modal with pre-fetched data
        const modalRef = this.modalCdsService.show(LicenceAgreementComponent, {
          customImageName: customImageName,
          licenseData: licenseData
        });
        modalRef.acceptanceEvent.subscribe((accepted: boolean) => {
          if (accepted) {
            this.licenseAccepted = true;
            this.startUpgrade();
          } else {
            // User declined - reset loading state
            this.upgradeForm.setErrors({ cdSubmitButton: true });
          }
        });
      },
      error: (error) => {
        // Image validation failed - show error in upgrade dialog
        this.upgradeForm.setErrors({ cdSubmitButton: true });
        this.imageFetchError = true;
        this.imageFetchErrorMessage =
          error?.error?.detail || 'Image may not exist or may not be accessible';
      }
    });
  }

  startUpgrade() {
    const version = this.upgradeForm.getValue('availableVersions');
    const image = this.upgradeForm.getValue('customImageName');
    this.upgradeService.start(version, image, this.licenseAccepted).subscribe({
      next: () => {
        this.notificationService.show(
          NotificationType.success,
          $localize`Started upgrading the cluster`
        );
      },
      error: (error) => {
        this.upgradeForm.setErrors({ cdSubmitButton: true });
        this.notificationService.show(
          NotificationType.error,
          $localize`Failed to start the upgrade`,
          error
        );
      },
      complete: () => {
        this.activeModal.close();
      }
    });
  }

  useImage() {
    this.showImageField = !this.showImageField;
    const availableVersionsControl = this.upgradeForm.get('availableVersions');
    const customImageNameControl = this.upgradeForm.get('customImageName');

    if (this.showImageField) {
      availableVersionsControl.disable();
      availableVersionsControl.clearValidators();

      customImageNameControl.setValidators(Validators.required);
      customImageNameControl.updateValueAndValidity();
    } else {
      availableVersionsControl.enable();
      availableVersionsControl.setValidators(Validators.required);
      availableVersionsControl.updateValueAndValidity();

      customImageNameControl.clearValidators();
    }
  }
}
