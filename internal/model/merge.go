package model

// Overrides is a sparse set of settings; nil means "not set" so explicit
// false, 0, "" or empty slices from a higher layer still win.
type Overrides struct {
	Skip        *bool
	Websockets  *bool
	Middlewares *[]string
	Rename      *string
	Name        *string
	Zone        *string
	Scheme      *string
	Port        *int
	SkipVerify  *bool
}

func pick[T any](vals ...*T) *T {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// Merge combines layers per field with precedence ui > cfg > label.
func Merge(label, cfg, ui Overrides) Overrides {
	return Overrides{
		Skip:        pick(ui.Skip, cfg.Skip, label.Skip),
		Websockets:  pick(ui.Websockets, cfg.Websockets, label.Websockets),
		Middlewares: pick(ui.Middlewares, cfg.Middlewares, label.Middlewares),
		Rename:      pick(ui.Rename, cfg.Rename, label.Rename),
		Name:        pick(ui.Name, cfg.Name, label.Name),
		Zone:        pick(ui.Zone, cfg.Zone, label.Zone),
		Scheme:      pick(ui.Scheme, cfg.Scheme, label.Scheme),
		Port:        pick(ui.Port, cfg.Port, label.Port),
		SkipVerify:  pick(ui.SkipVerify, cfg.SkipVerify, label.SkipVerify),
	}
}

func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// Apply returns svc with every set override applied.
func Apply(svc Service, o Overrides) Service {
	set(&svc.Name, o.Name)
	set(&svc.Zone, o.Zone)
	set(&svc.Backend.Scheme, o.Scheme)
	set(&svc.Backend.Port, o.Port)
	set(&svc.Backend.SkipVerify, o.SkipVerify)
	set(&svc.Options.Skip, o.Skip)
	set(&svc.Options.Websockets, o.Websockets)
	set(&svc.Options.Rename, o.Rename)
	if o.Middlewares != nil {
		svc.Options.Middlewares = append([]string{}, *o.Middlewares...)
	}
	return svc
}
