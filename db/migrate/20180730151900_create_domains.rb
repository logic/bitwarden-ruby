class CreateDomains < ActiveRecord::Migration[5.1]
  def change
    create_table :equiv_domains, id: string, primary_key: :uuid do |t|
      t.string :user_uuid
    end
    add_foreign_key :equiv_domains, :users { column: :user_uuid, primary_key: :uuid }
    add_index(:equiv_domains, :user_uuid)

    create_table :equiv_domain_names, id: string, primary_key: :uuid do |t|
      t.string :domain
      t.string :domain_uuid
    end
    add_foreign_key :equiv_domain_names, :equiv_domains, { column: :domain_uuid, primary_key: :uuid }
    add_index(:equiv_domain_names, :domain_uuid)
  end
end
