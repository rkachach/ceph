import { Component } from '@angular/core';

@Component({
  selector: 'cd-login-layout',
  templateUrl: './login-layout.component.html',
  styleUrls: ['./login-layout.component.scss'],
  standalone: false
})
export class LoginLayoutComponent {
  docItems: any[] = [
    { section: 'help', text: $localize`Help` },
    { section: 'terms', text: $localize`Terms of Use` },
    { section: 'privacy', text: $localize`Privacy Policy` }
  ];
}
